import { IsPhoneNumber, IsString, IsNotEmpty, MinLength} from "class-validator";

export class RegisterDto {
    @IsPhoneNumber('VN', {message: 'Phone number must be valid'})
    phone: string;
    @IsString({message: 'Full name must be a string'})
    @IsNotEmpty({message: 'Full name must not be empty'})
    name: string;
    @IsString({message: 'Password must be a string'})
    @IsNotEmpty({message: 'Password must not be empty'})
    @MinLength(6, {message: 'Password must be at least 6 characters long'})
    password: string;
}