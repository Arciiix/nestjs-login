import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { User } from "@prisma/client";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import * as argon from "argon2";
import { PrismaService } from "src/prisma/prisma.service";
import { UserDto } from "./dto/user.dto";
import { UserLoginDto } from "./dto/userLogin.dto";

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService
  ) {}

  async login(payload: UserLoginDto): Promise<{
    user: User;
    refreshToken: string;
    accessToken: string;
  }> {
    const user = await this.prisma.user.findFirst({
      where: {
        OR: [
          {
            email: payload.email,
          },
          {
            login: payload.login,
          },
        ],
      },
    });

    if (!user) {
      throw new NotFoundException("User not found");
    }

    const isValid = await argon.verify(user.password, payload.password);

    if (!isValid) {
      throw new UnauthorizedException("Invalid password");
    }

    const refreshToken = await this.generateRefreshToken(user);
    const accessToken = await this.generateAccessToken(refreshToken);

    user.password = null; //Don't send the password hash back to user
    user.currentRefreshToken = null; //Don't send the refresh token back as well

    return {
      user,
      refreshToken,
      accessToken,
    };
  }

  async addUser(
    user: UserDto
  ): Promise<{ user: User; refreshToken: string; accessToken: string }> {
    try {
      const hash = await argon.hash(user.password);

      const userObj: User = await this.prisma.user.create({
        data: { ...user, ...{ password: hash } },
      });

      userObj.password = null; //Don't send the password hash back to user
      userObj.currentRefreshToken = null; //Don't send the refresh token back as well

      const refreshToken = await this.generateRefreshToken(userObj);

      return {
        user: userObj,
        refreshToken: refreshToken,
        accessToken: await this.generateAccessToken(refreshToken),
      };
    } catch (err) {
      console.error(err);
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === "P2002") {
          throw new ConflictException("User already exists");
        }
      }
    }
  }

  async generateAccessToken(refreshToken: string): Promise<string> {
    if (!refreshToken) {
      throw new BadRequestException("No refresh token provided");
    }

    let refreshTokenPayload;
    try {
      refreshTokenPayload = await this.jwt.verifyAsync(refreshToken, {
        secret: this.config.get("JWT_REFRESH_SECRET"),
      });
    } catch (err) {
      console.error(err);
      throw new UnauthorizedException("Invalid refresh token");
    }

    if (!refreshTokenPayload) {
      throw new UnauthorizedException("Invalid refresh token");
    } else {
      const user = await this.prisma.user.findFirst({
        where: {
          id: refreshTokenPayload.id,
        },
      });

      if (!user) {
        throw new NotFoundException("User not found");
      }

      const isValid = await argon.verify(
        user.currentRefreshToken,
        refreshToken
      );

      if (!isValid) {
        throw new UnauthorizedException("Invalid refresh token");
      }

      const payload: JwtPayload = {
        id: refreshTokenPayload.id,
        login: refreshTokenPayload.login,
      };
      return await this.jwt.signAsync(payload, {
        expiresIn: "15m",
        secret: this.config.get("JWT_ACCESS_SECRET"),
      });
    }
  }

  async generateRefreshToken(user: User): Promise<string> {
    const payload: JwtPayload = {
      id: user.id,
      login: user.login,
    };

    const token: string = await this.jwt.signAsync(payload, {
      expiresIn: "30d",
      secret: this.config.get("JWT_REFRESH_SECRET"),
    });

    await this.prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        currentRefreshToken: await argon.hash(token),
      },
    });

    return token;
  }

  async logout(userId: string, refreshToken: string): Promise<void> {
    if (!userId) {
      throw new InternalServerErrorException("No user id found in request");
    }

    const tokenOwner = await this.prisma.user.findFirst({
      where: { id: userId },
    });
    if (!tokenOwner) {
      throw new NotFoundException("User not found");
    }

    if (!(await argon.verify(tokenOwner.currentRefreshToken, refreshToken))) {
      throw new BadRequestException("Wrong refresh token");
    }

    await this.prisma.user.update({
      where: {
        id: tokenOwner.id,
      },
      data: {
        currentRefreshToken: null,
      },
    });
  }

  async validateUser(jwtPayload: JwtPayload): Promise<User> {
    const userObj = await this.prisma.user.findFirst({
      where: {
        id: jwtPayload.id,
      },
    });

    userObj.password = null; //Don't send the password hash back to user
    userObj.currentRefreshToken = null; //Don't send the refresh token back as well

    return userObj;
  }

  async getMe(accessToken: string): Promise<User> {
    if (!accessToken) {
      throw new BadRequestException("No access token provided");
    }

    let accessTokenPayload;
    try {
      accessTokenPayload = await this.jwt.verifyAsync(accessToken, {
        secret: this.config.get("JWT_ACCESS_SECRET"),
      });
    } catch (err) {
      console.error(err);
      throw new UnauthorizedException("Invalid access token");
    }

    if (!accessTokenPayload) {
      throw new UnauthorizedException("Invalid access token");
    } else {
      const user = await this.prisma.user.findFirst({
        where: {
          id: accessTokenPayload.id,
        },
      });
      if (!user) {
        throw new NotFoundException("User not found");
      }
      return user;
    }
  }
}

interface JwtPayload {
  id: string;
  login: string;
}

export type { JwtPayload };
