import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  UseGuards,
  Request,
  Response,
  UnauthorizedException,
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
  async login(
    @Response({ passthrough: true }) res,
    @Body() payload: UserLoginDto
  ): Promise<{
    user: User;
    refreshToken: string;
    accessToken: string;
  }> {
    const returnObj = await this.authService.login(payload);
    res.cookie("accessToken", returnObj.accessToken, {
      httpOnly: true,
      maxAge: 1000 * 15,
    });
    res.cookie("refreshToken", returnObj.refreshToken, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });
    return returnObj;
  }

  @Post("/addUser")
  async addUser(
    @Response({ passthrough: true }) res,
    @Body() user: UserDto
  ): Promise<{ user: User; refreshToken: string; accessToken: string }> {
    const returnObj = await this.authService.addUser(user);
    res.cookie("accessToken", returnObj.accessToken, {
      httpOnly: true,
      maxAge: 1000 * 15,
    });
    res.cookie("refreshToken", returnObj.refreshToken, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });

    return returnObj;
  }

  @Delete("/logout")
  async logout(
    @Request() req,
    @Response({ passthrough: true }) res,
    @Body("refreshToken") refreshToken: string
  ): Promise<{ success: boolean }> {
    refreshToken = refreshToken ?? req.cookies.refreshToken;
    if (!refreshToken) {
      throw new UnauthorizedException("No refresh token provided");
    }
    await this.authService.logout(refreshToken);
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    return { success: true };
  }

  @Get("/generateAccessToken/:refreshToken")
  async generateAccessToken(
    @Response({ passthrough: true }) res,
    @Param("refreshToken") refreshToken: string
  ): Promise<{ accessToken: string }> {
    const accessToken = await this.authService.generateAccessToken(
      refreshToken
    );
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      maxAge: 1000 * 15,
    });

    return {
      accessToken: accessToken,
    };
  }

  @UseGuards(LocalAuthGuard)
  @Get("/me")
  async getMe(@Request() req): Promise<any> {
    return req.user;
  }
}
