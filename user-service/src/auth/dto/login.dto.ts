import {IsPhoneNumber, IsNotEmpty} from 'class-validator';

export class LoginDto {
    @IsPhoneNumber('VN', {message: 'Phone number must be valid'})
    phone: string;

    @IsNotEmpty({message: 'Password must not be empty'})
    password: string;
}