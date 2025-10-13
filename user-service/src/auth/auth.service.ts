import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { JwtService } from "@nestjs/jwt";
import { Model } from "mongoose";
import * as bcrypt from "bcrypt";
import { User } from "../user/user.schema";
import { RegisterDto } from "./dto/register.dto";
import { LoginDto } from "./dto/login.dto";
import {VerifyOtpDto} from "./dto/verifyotp.dto";

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private jwtService: JwtService
    ) {}

    async register(RegisterDto: RegisterDto) { 
        const { phone, name, password } = RegisterDto;
        const existingPhone = await this.userModel.findOne({phone});
        if (existingPhone) {
            throw new BadRequestException('Phone number already exists');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const otpcode = Math.floor(10000 + Math.random() * 90000).toString();
        const otpcode_expiry = new Date(Date.now() + 10 * 60 * 1000);

        const newUser = new this.userModel({
            phone,
            name: name,
            password: hashedPassword,
            otpcode: otpcode,
            otpcode_expiry: otpcode_expiry,
            isPhoneVerified: false,
            isDriver: false,
            isActive: false
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
        return this.jwtService.sign(payload, { expiresIn: '15m' });
    }

    private createRefreshToken(payload: any) {
        return this.jwtService.sign(payload, { expiresIn: '7d' });
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
        user.isActive = true;
        await user.save();

        return { accessToken, refreshToken, name: user.name, phone: user.phone, isDriver: user.isDriver, avatar: user.avatar};
    }
}
