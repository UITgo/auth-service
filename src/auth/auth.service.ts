import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { JwtService } from "@nestjs/jwt";
import { Model } from "mongoose";
import * as bcrypt from "bcrypt";
import { User } from "../user/user.schema";
import { RegisterDto } from "./dto/register.dto";
import { LoginDto } from "./dto/login.dto";
import {VerifyOtpDto} from "./dto/verifyotp.dto";
import { ResendOtpDto } from "./dto/resend-otp.dto";
import { ConfigService } from "@nestjs/config";
import { RefreshTokenDto } from "./dto/refreshtoken.dto";
@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private jwtService: JwtService,
        private readonly configService: ConfigService
    ) {}

    async register(RegisterDto: RegisterDto) { 
        const { phone, password, isDriver } = RegisterDto;
        const existingPhone = await this.userModel.findOne({phone});
        if (existingPhone) {
            throw new BadRequestException('Phone number already exists');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const otpcode = Math.floor(10000 + Math.random() * 90000).toString();
        const otpcode_expiry = new Date(Date.now() + 10 * 60 * 1000);

        const newUser = new this.userModel({
            phone,
            password: hashedPassword,
            otpcode: otpcode,
            otpcode_expiry: otpcode_expiry,
            isPhoneVerified: false,
            isDriver: isDriver
        });
        await newUser.save();
        return {message: 'User registered successfully, please verify your phone number'};
    }

    async verifyOtp(VerifyOtpDto: VerifyOtpDto) {
        const { phone, otpcode } = VerifyOtpDto;
        const user = await this.userModel.findOne({phone});
        if (!user) {
            throw new BadRequestException('User not found');
        }
        if (user.isPhoneVerified) {
            throw new BadRequestException('Phone number already verified');
        }
        if (user.otpcode !== otpcode || new Date() > user.otpcode_expiry!) {
            throw new BadRequestException('Invalid OTP code or OTP has expired');
        }

        user.isPhoneVerified = true;
        user.otpcode = undefined;
        user.otpcode_expiry = undefined;
        await user.save();
        return {message: 'Phone number verified successfully'};
    }

    private createAccessToken(payload: any) {
        return this.jwtService.sign(payload, {
        secret: this.configService.get<string>('JWT_SECRET'),
        expiresIn: '15m',
        });
    }

    private createRefreshToken(payload: any) {
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
            expiresIn: '7d',
        });
    }

    async login(LoginDto: LoginDto) {
        const { phone, password } = LoginDto;
        const user = await this.userModel.findOne({phone});
        if (!user) {
            throw new BadRequestException('User not found');
        }
        if (!user.isPhoneVerified) {
            throw new UnauthorizedException('Phone number not verified');
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            throw new UnauthorizedException('Invalid password');
        }
        const accessToken = this.createAccessToken({ id: user._id });
        const refreshToken = this.createRefreshToken({ id: user._id });
    
        user.refreshToken = refreshToken;
        await user.save();

        return { accessToken, refreshToken, phone: user.phone, isDriver: user.isDriver};
    }

    async resendOtp(RegisterDto: ResendOtpDto) {
        const { phone } = RegisterDto;
        const user = await this.userModel.findOne({phone});
        if (!user) {
            throw new BadRequestException('User not found');
        }
        if (user.isPhoneVerified) {
            throw new BadRequestException('Phone number already verified');
        }
        const otpcode = Math.floor(10000 + Math.random() * 90000).toString();
        const otpcode_expiry = new Date(Date.now() + 10 * 60 * 1000);
        user.otpcode = otpcode;
        user.otpcode_expiry = otpcode_expiry;
        await user.save();
        return {message: 'OTP code resent successfully'};
    }

    async refreshToken(oldRefreshToken: string) {
        try {
            const payload = this.jwtService.verify(oldRefreshToken, {secret: this.configService.get('JWT_REFRESH_SECRET')});
            const user = await this.userModel.findById(payload.id);
            if (!user || user.refreshToken !== oldRefreshToken) {
                throw new UnauthorizedException('Invalid refresh token');
            }
            const newAccessToken = this.createAccessToken({ id: user._id });
            const newRefreshToken = this.createRefreshToken({ id: user._id });
            user.refreshToken = newRefreshToken;
            await user.save();
            return { accessToken: newAccessToken, refreshToken: newRefreshToken };
        } catch (error) {
            throw new UnauthorizedException('Invalid refresh token');
        }
    }
}
