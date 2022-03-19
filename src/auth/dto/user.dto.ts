import { IsNotEmpty, IsEmail, Length, IsString } from "class-validator";

export class UserDto {
  @IsNotEmpty()
  @IsString()
  login: string;

  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @Length(8, 32)
  password: string;
}
