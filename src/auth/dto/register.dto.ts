import { IsPhoneNumber, IsEmail, IsString, IsNotEmpty, MinLength} from "class-validator";

export class RegisterDto {
    @IsEmail()
    email: string
    @IsPhoneNumber('VN', {message: 'Phone number must be valid'})
    phone: string;
    @IsString({message: 'Password must be a string'})
    @IsNotEmpty({message: 'Password must not be empty'})
    @MinLength(6, {message: 'Password must be at least 6 characters long'})
    password: string;
    @IsNotEmpty({message: 'isDriver must not be empty'})
    isDriver: boolean;
}