import {
  Body,
  Controller,
  Delete,
  Get,
  Post,
  UseGuards,
  Request,
  Response,
  HttpCode,
  Put,
  BadRequestException,
} from "@nestjs/common";
import { AuthService } from "./auth.service";
import {
  ISuccessReturnType,
  ITwoFactorAuthInfo,
  IUserReturnType,
} from "./auth";
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
  ): Promise<IUserReturnType> {
    const returnObj = await this.authService.login(payload);
    res.cookie("accessToken", returnObj.accessToken, {
      httpOnly: true,
      maxAge: 1000 * 60 * 15,
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
  ): Promise<IUserReturnType> {
    const returnObj = await this.authService.addUser(user);
    res.cookie("accessToken", returnObj.accessToken, {
      httpOnly: true,
      maxAge: 1000 * 60 * 15,
    });
    res.cookie("refreshToken", returnObj.refreshToken, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });

    return returnObj;
  }

  @UseGuards(LocalAuthGuard)
  @Delete("/logout")
  async logout(
    @Request() req,
    @Response({ passthrough: true }) res
  ): Promise<ISuccessReturnType> {
    await this.authService.logout(
      req.user.id,
      this.authService.getRefreshTokenFromRequest(req)
    );
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    return { success: true };
  }

  @UseGuards(LocalAuthGuard)
  @Delete("/logoutFromAllDevices")
  async logoutFromAllDevices(
    @Request() req,
    @Response({ passthrough: true }) res
  ): Promise<ISuccessReturnType & { amountOfDevices: number }> {
    const { amountOfDevices } = await this.authService.logoutFromAllDevices(
      req.user.id
    );
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    return { success: true, amountOfDevices };
  }

  @Get("/generateAccessToken")
  async generateAccessToken(
    @Request() req,
    @Response({ passthrough: true }) res
  ): Promise<{ accessToken: string; isAuthenticated: boolean }> {
    const refreshToken = this.authService.getRefreshTokenFromRequest(req);

    const isAuthenticated =
      await this.authService.checkIfRefreshTokenIsAuthenticated(refreshToken);
    const accessToken = await this.authService.generateAccessToken(
      refreshToken,
      isAuthenticated
    );
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      maxAge: 1000 * 60 * 15,
    });
    return {
      accessToken: accessToken,
      isAuthenticated: isAuthenticated,
    };
  }

  @UseGuards(LocalAuthGuard)
  @Get("/me")
  async getMe(@Request() req): Promise<any> {
    return req.user;
  }

  @UseGuards(LocalAuthGuard)
  @Post("/2fa/generate")
  @HttpCode(200)
  async generate2FA(@Request() req): Promise<ITwoFactorAuthInfo> {
    return await this.authService.generate2FA(req.user.id);
  }

  @UseGuards(LocalAuthGuard)
  @Get("/2fa/info")
  async get2FARecoveryCode(@Request() req): Promise<ITwoFactorAuthInfo> {
    return await this.authService.get2FAInfo(req.user.id);
  }

  @UseGuards(LocalAuthGuard)
  @Put("/2fa/toogle")
  @HttpCode(200)
  async toogle2FA(
    @Request() req,
    @Body("isEnabled") isEnabled: boolean
  ): Promise<ITwoFactorAuthInfo> {
    if (isEnabled === undefined || isEnabled === null) {
      throw new BadRequestException("isEnabled is required");
    }
    return await this.authService.toogle2FA(req.user.id, isEnabled);
  }

  @Get("/2fa/login")
  async loginWith2FA(
    @Request() req,
    @Response({ passthrough: true }) res,
    @Body("code") code?: string,
    @Body("recoveryCode") recoveryCode?: string
  ): Promise<IUserReturnType> {
    const accessToken = this.authService.getAccessTokenFromRequest(req);

    const returnObj: IUserReturnType = await this.authService.loginWith2FA(
      accessToken,
      code,
      recoveryCode
    );
    res.cookie("accessToken", returnObj.accessToken, {
      httpOnly: true,
      maxAge: 1000 * 60 * 15,
    });
    res.cookie("refreshToken", returnObj.refreshToken, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });
    return returnObj;
  }
}
