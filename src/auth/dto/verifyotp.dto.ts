import {IsNotEmpty} from 'class-validator';

export class VerifyOtpDto {
    @IsNotEmpty({message: 'Phone number must not be empty'})
    phone: string;
    @IsNotEmpty({message: 'OTP must not be empty'})
    otpcode: string;
}