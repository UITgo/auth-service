import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import * as bcrypt from "bcrypt";
import { User } from "../user/user.schema";
import { RegisterDto } from "./dto/register.dto";
import { LoginDto } from "./dto/login.dto";
import { VerifyOtpDto } from "./dto/verifyotp.dto";
import { ConfigService } from "@nestjs/config";
import { CognitoUserPool, CognitoUser, CognitoUserAttribute, AuthenticationDetails, CognitoRefreshToken } from 'amazon-cognito-identity-js';

@Injectable()
export class AuthService {
    private userPool: CognitoUserPool;
    
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private configService: ConfigService
    ) {
        this.userPool = new CognitoUserPool({
            UserPoolId: this.configService.get<string>('USER_POOL_ID')!,
            ClientId: this.configService.get<string>('CLIENT_ID')!,
        });
    }

    async register(registerDto: RegisterDto) { 
        const { email, phone, password, isDriver } = registerDto;
        const existingUser = await this.userModel.findOne({ email });
        if (existingUser) {
            throw new BadRequestException('Email already exists');
        }
        const attributeList = [
            new CognitoUserAttribute({ Name: 'email', Value: email })
        ];

        return new Promise((resolve, reject) => {
            this.userPool.signUp(email, password, attributeList, [], async (err, result) => {
                if (err) {
                    return reject(new BadRequestException(err.message || err));
                }
            
                const newUser = new this.userModel({
                    email,
                    phone,
                    password: await bcrypt.hash(password, 10),
                    isEmailVerified: false,
                    isDriver,
                });
                await newUser.save();

                resolve({ 
                    message: 'User registered successfully. Please check your email for verification code.',
                    email: email
                });
            });
        });
    }

    async verifyOtp(verifyOtpDto: VerifyOtpDto) {
        const { email, otpcode } = verifyOtpDto;
        const user = await this.userModel.findOne({ email });
        if (!user) {
            throw new BadRequestException('User not found');
        }
        const cognitoUser = new CognitoUser({ 
            Username: email, 
            Pool: this.userPool 
        });
        return new Promise((resolve, reject) => {
            cognitoUser.confirmRegistration(otpcode, true, async (err, result) => {
                if (err) {
                    return reject(new BadRequestException(err.message || 'Invalid verification code'));
                }
                user.isEmailVerified = true;
                await user.save();

                resolve({ 
                    message: 'Email verified successfully',
                    verified: true 
                });
            });
        });
    }

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
            Pool: this.userPool 
        });
        
        const authDetails = new AuthenticationDetails({ 
            Username: email, 
            Password: password 
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
                            isEmailVerified: user.isEmailVerified
                        }
                    });
                },
                onFailure: (err) => {
                    reject(new UnauthorizedException(err.message || 'Login failed'));
                },
            });
        });
    }

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
            Pool: this.userPool 
        });

        return new Promise((resolve, reject) => {
            cognitoUser.resendConfirmationCode((err, result) => {
                if (err) {
                    return reject(new BadRequestException(err.message || 'Failed to resend code'));
                }
                resolve({ 
                    message: 'Verification code resent successfully. Please check your email.',
                    email: email
                });
            });
        });
    }

    async refreshToken(refreshToken: string) {
    return new Promise((resolve, reject) => {
        const cognitoUser = new CognitoUser({
            Username: '', 
            Pool: this.userPool
        });
        const RefreshToken = new CognitoRefreshToken({ 
            RefreshToken: refreshToken 
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
}