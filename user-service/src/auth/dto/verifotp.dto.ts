import {IsNotEmpty} from 'class-validator';

export class VerifOtpDto {
    @IsNotEmpty({message: 'OTP must not be empty'})
    otp: string;
}