import { IsNotEmpty, IsEmail, IsString, ValidateIf } from "class-validator";

export class UserLoginDto {
  @ValidateIf((o) => !o.email || o.login)
  @IsString()
  login: string;

  @ValidateIf((o) => !o.login || o.email)
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;
}
