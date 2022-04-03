import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  UseGuards,
  Request,
} from "@nestjs/common";
import { User } from "@prisma/client";
import { AuthService } from "./auth.service";
import { UserDto } from "./dto/user.dto";
import { UserLoginDto } from "./dto/userLogin.dto";
import { LocalAuthGuard } from "./guards/localAuth.guard";

@Controller("auth")
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post("/login")
  async login(@Body() payload: UserLoginDto): Promise<{
    user: User;
    refreshToken: string;
    accessToken: string;
  }> {
    return await this.authService.login(payload);
  }

  @Post("/addUser")
  async addUser(
    @Body() user: UserDto
  ): Promise<{ user: User; refreshToken: string; accessToken: string }> {
    return await this.authService.addUser(user);
  }

  @Delete("/logout")
  async logout(
    @Body("refreshToken") refreshToken: string
  ): Promise<{ success: boolean }> {
    await this.authService.logout(refreshToken);
    return { success: true };
  }

  @Get("/generateAccessToken/:refreshToken")
  async generateAccessToken(
    @Param("refreshToken") refreshToken: string
  ): Promise<{ accessToken: string }> {
    return {
      accessToken: await this.authService.generateAccessToken(refreshToken),
    };
  }

  @UseGuards(LocalAuthGuard)
  @Get("/me")
  async getMe(@Request() req): Promise<any> {
    return req.user;
  }
}
