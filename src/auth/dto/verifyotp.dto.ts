import {IsNotEmpty} from 'class-validator';

export class VerifyOtpDto {
    @IsNotEmpty({message: 'Email must not be empty'})
    email: string;
    @IsNotEmpty({message: 'OTP must not be empty'})
    otpcode: string;
}