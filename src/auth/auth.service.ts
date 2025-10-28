import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';

import { User, UserDocument } from '../user/user.schema';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyOtpDto } from './dto/verifyotp.dto';

// Cognito SDK (identity-js cho flow sẵn có)
import {
  AuthenticationDetails,
  CognitoRefreshToken,
  CognitoUser,
  CognitoUserAttribute,
  CognitoUserPool,
} from 'amazon-cognito-identity-js';

// AWS SDK v3 (bổ sung các thao tác admin/group, refresh v2, get status)
import {
  CognitoIdentityProviderClient,
  AdminAddUserToGroupCommand,
  AdminGetUserCommand,
  InitiateAuthCommand,
} from '@aws-sdk/client-cognito-identity-provider';

// decode JWT (không verify chữ ký vì đã verify ở API Gateway/JWKS upstream)
import { jwtDecode } from 'jwt-decode';

type JWTPayload = {
  sub: string;
  email?: string;
  'cognito:username'?: string;
  'cognito:groups'?: string[];
};

@Injectable()
export class AuthService {
  private userPool: CognitoUserPool;
  // Bổ sung: client AWS SDK v3 để thực hiện thao tác admin (add group, get user, refresh v2)
  private readonly cognito = new CognitoIdentityProviderClient({});

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    private readonly configService: ConfigService,
  ) {
    this.userPool = new CognitoUserPool({
      UserPoolId: this.configService.get<string>('USER_POOL_ID')!,
      ClientId: this.configService.get<string>('CLIENT_ID')!,
    });
  }

  private get pool() {
    return {
      userPoolId: this.configService.get<string>('USER_POOL_ID')!,
      clientId: this.configService.get<string>('CLIENT_ID')!,
    };
  }

  /** Đăng ký: giữ nguyên flow identity-js hiện có, đồng thời lưu cognitoSub vào DB để đồng bộ đa service */
  async register(registerDto: RegisterDto) {
    const { email, phone, password, isDriver } = registerDto;

    const existingUser = await this.userModel.findOne({ email });
    if (existingUser) {
      throw new BadRequestException('Email already exists');
    }

    const attributeList = [
      new CognitoUserAttribute({ Name: 'email', Value: email }),
      ...(phone ? [new CognitoUserAttribute({ Name: 'phone_number', Value: phone })] : []),
    ];

    return new Promise((resolve, reject) => {
      this.userPool.signUp(email, password, attributeList, [], async (err, result) => {
        if (err || !result) {
          return reject(new BadRequestException(err?.message || err || 'Sign up failed'));
        }

        // Bổ sung: lấy userSub từ kết quả signUp của identity-js
        // (amazon-cognito-identity-js trả về result.userSub)
        const cognitoSub: string | undefined = (result as any)?.userSub;

        const newUser = new this.userModel({
          email,
          phone,
          password: await bcrypt.hash(password, 10), // giữ nguyên logic lưu hash
          isEmailVerified: false,
          isDriver,
          // Bổ sung: lưu cognitoSub để đồng bộ ID
          ...(cognitoSub ? { cognitoSub } : {}),
        });
        await newUser.save();

        resolve({
          message: 'User registered successfully. Please check your email for verification code.',
          email,
          // Trả thêm hint needVerify cho client (không phá compat cũ)
          needVerify: true,
        });
      });
    });
  }

  /** Xác thực OTP: giữ nguyên confirmRegistration; bổ sung add vào group `driver` nếu user.isDriver */
  async verifyOtp(verifyOtpDto: VerifyOtpDto) {
    const { email, otpcode } = verifyOtpDto;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    const cognitoUser = new CognitoUser({
      Username: email,
      Pool: this.userPool,
    });

    return new Promise((resolve, reject) => {
      cognitoUser.confirmRegistration(otpcode, true, async (err, _result) => {
        if (err) {
          return reject(new BadRequestException(err.message || 'Invalid verification code'));
        }

        user.isEmailVerified = true;
        await user.save();

        // Bổ sung: nếu là tài xế, add vào group `driver` để token có 'cognito:groups'
        if (user.isDriver) {
          try {
            await this.cognito.send(
              new AdminAddUserToGroupCommand({
                UserPoolId: this.pool.userPoolId,
                Username: email,
                GroupName: 'driver',
              }),
            );
          } catch {
            // không làm fail verify; chỉ log/nuốt lỗi nhóm để tránh phá flow cũ
          }
        }

        resolve({
          message: 'Email verified successfully',
          verified: true,
        });
      });
    });
  }

  /** Đăng nhập: giữ nguyên flow identity-js */
  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    if (!user.isEmailVerified) {
      throw new UnauthorizedException('Please verify your email first');
    }

    const cognitoUser = new CognitoUser({
      Username: email,
      Pool: this.userPool,
    });

    const authDetails = new AuthenticationDetails({
      Username: email,
      Password: password,
    });

    return new Promise((resolve, reject) => {
      cognitoUser.authenticateUser(authDetails, {
        onSuccess: async (result) => {
          const accessToken = result.getAccessToken().getJwtToken();
          const idToken = result.getIdToken().getJwtToken();
          const refreshToken = result.getRefreshToken().getToken();

          resolve({
            accessToken,
            idToken,
            refreshToken,
            user: {
              email: user.email,
              isDriver: user.isDriver,
              isEmailVerified: user.isEmailVerified,
            },
          });
        },
        onFailure: (err) => {
          reject(new UnauthorizedException(err.message || 'Login failed'));
        },
      });
    });
  }

  /** Gửi lại mã OTP: giữ nguyên resend của identity-js */
  async resendOtp(email: string) {
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('User not found');
    }
    if (user.isEmailVerified) {
      throw new BadRequestException('Email already verified');
    }

    const cognitoUser = new CognitoUser({
      Username: email,
      Pool: this.userPool,
    });

    return new Promise((resolve, reject) => {
      cognitoUser.resendConfirmationCode((err, _result) => {
        if (err) {
          return reject(new BadRequestException(err.message || 'Failed to resend code'));
        }
        resolve({
          message: 'Verification code resent successfully. Please check your email.',
          email,
        });
      });
    });
  }

  async refreshToken(refreshToken: string, email: string) {
    return new Promise((resolve, reject) => {
      const cognitoUser = new CognitoUser({
        Username: email, 
        Pool: this.userPool,
      });
      const RefreshToken = new CognitoRefreshToken({
        RefreshToken: refreshToken,
      });

      cognitoUser.refreshSession(RefreshToken, (err, session) => {
        if (err) {
          return reject(new UnauthorizedException('Refresh token expired or invalid'));
        }

        const newAccessToken = session.getAccessToken().getJwtToken();
        const newIdToken = session.getIdToken().getJwtToken();

        resolve({
          accessToken: newAccessToken,
          idToken: newIdToken,
        });
      });
    });
  }

  /** Bổ sung (tùy chọn): Refresh token qua AWS SDK v3 (REFRESH_TOKEN_AUTH) — cần có email */
  async refreshTokenV2(refreshToken: string, email: string) {
    if (!refreshToken || !email) {
      throw new BadRequestException('refreshToken and email are required');
    }
    const res = await this.cognito.send(
      new InitiateAuthCommand({
        AuthFlow: 'REFRESH_TOKEN_AUTH',
        ClientId: this.pool.clientId,
        AuthParameters: {
          REFRESH_TOKEN: refreshToken,
          USERNAME: email,
        },
      }),
    );
    if (!res.AuthenticationResult) {
      throw new UnauthorizedException('REFRESH_FAILED');
    }
    return {
      accessToken: res.AuthenticationResult.AccessToken,
      idToken: res.AuthenticationResult.IdToken,
      expiresIn: res.AuthenticationResult.ExpiresIn,
      tokenType: res.AuthenticationResult.TokenType,
    };
  }

  /** Bổ sung: Tiện ích xem trạng thái user ở Cognito (không thay thế resendOtp) */
  async getUserStatus(email: string) {
    const user = await this.cognito.send(
      new AdminGetUserCommand({
        UserPoolId: this.pool.userPoolId,
        Username: email,
      }),
    );
    return { email, status: user.UserStatus };
  }

  /** Bổ sung: /auth/me — trả claim cơ bản để client/service khác check nhanh */
  me(authorization?: string) {
    if (!authorization?.startsWith('Bearer ')) {
      throw new UnauthorizedException();
    }
    const token = authorization.slice('Bearer '.length);
    const payload = jwtDecode<JWTPayload>(token);
    return {
      sub: payload.sub || payload['cognito:username'],
      email: payload.email,
      groups: payload['cognito:groups'] || [],
    };
  }
}
