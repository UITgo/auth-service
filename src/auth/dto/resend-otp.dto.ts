import { IsPhoneNumber } from "class-validator";

export class ResendOtpDto {
  @IsPhoneNumber("VN")
  phone: string;
}