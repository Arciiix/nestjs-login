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
import { authenticator } from "otplib";
import { PrismaService } from "src/prisma/prisma.service";
import { UserDto } from "./dto/user.dto";
import { UserLoginDto } from "./dto/userLogin.dto";
import * as crypto from "crypto";
import * as QRCode from "qrcode";
import { IJwtPayload, ITwoFactorAuthInfo, IUserReturnType } from "./auth";

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService
  ) {}

  async login(payload: UserLoginDto): Promise<IUserReturnType> {
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

    return {
      user: {
        id: user.id,
        email: user.email,
        login: user.login,
      },
      refreshToken,
      accessToken,
    };
  }

  async addUser(user: UserDto): Promise<IUserReturnType> {
    try {
      const hash = await argon.hash(user.password);

      const userObj: User = await this.prisma.user.create({
        data: { ...user, ...{ password: hash } },
      });

      userObj.password = null; //Don't send the password hash back to user

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
        include: {
          refreshTokens: true,
        },
      });

      if (!user) {
        throw new NotFoundException("User not found");
      }

      let isValid = false;

      for await (const token of user.refreshTokens) {
        if (!isValid) {
          isValid = await argon.verify(token.hashedToken, refreshToken);
        }
      }

      if (!isValid) {
        throw new UnauthorizedException("Invalid refresh token");
      }

      const payload: IJwtPayload = {
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
    //There's a limit of maxium refresh tokens per user
    const numberOfTokens = await this.prisma.refreshToken.count({
      where: {
        user: {
          id: user.id,
        },
      },
    });

    if (
      numberOfTokens >=
      (parseInt(this.config.get("MAX_REFRESH_TOKENS_PER_USER")) || 20)
    ) {
      const firstSession = await this.prisma.refreshToken.findFirst({
        where: {
          userId: user.id,
        },
      });
      await this.prisma.refreshToken.delete({
        where: {
          hashedToken: firstSession.hashedToken,
        },
      });
      console.log(
        `User ${user.id} has exceeded the total allowed amount of refresh tokens - deleting the first one!`
      );
    }

    const payload: IJwtPayload = {
      id: user.id,
      login: user.login,
    };

    const token: string = await this.jwt.signAsync(payload, {
      expiresIn: "30d",
      secret: this.config.get("JWT_REFRESH_SECRET"),
    });

    await this.prisma.refreshToken.create({
      data: {
        hashedToken: await argon.hash(token),
        user: {
          connect: {
            id: user.id,
          },
        },
      },
    });

    return token;
  }

  async logout(userId: string, refreshToken: string): Promise<void> {
    if (!userId) {
      throw new InternalServerErrorException("No user id found in request");
    }

    const tokens = await this.prisma.refreshToken.findMany({
      where: {
        user: {
          id: userId,
        },
      },
    });

    if (!tokens) {
      throw new NotFoundException("No refresh tokens found");
    }

    let didDelete = false;

    for await (const token of tokens) {
      if (await argon.verify(token.hashedToken, refreshToken)) {
        await this.prisma.refreshToken.delete({
          where: {
            hashedToken: token.hashedToken,
          },
        });
        didDelete = true;
      }
    }

    if (!didDelete) {
      throw new UnauthorizedException("Invalid refresh token");
    }
  }

  async logoutFromAllDevices(
    userId: string
  ): Promise<{ amountOfDevices: number }> {
    if (!userId) {
      throw new InternalServerErrorException("No user id found in request");
    }

    const { count } = await this.prisma.refreshToken.deleteMany({
      where: {
        user: {
          id: userId,
        },
      },
    });

    return { amountOfDevices: count };
  }

  async validateUser(jwtPayload: IJwtPayload): Promise<User> {
    const userObj = await this.prisma.user.findFirst({
      where: {
        id: jwtPayload.id,
      },
    });

    userObj.password = null; //Don't send the password hash back to user

    return userObj;
  }

  async generate2FA(userId: string): Promise<ITwoFactorAuthInfo> {
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
      },
    });

    if (!user) {
      throw new NotFoundException("User not found");
    }

    const secret = await authenticator.generateSecret();
    const uri = await authenticator.keyuri(
      user.login,
      this.config.get("APP_NAME") ?? "NestJS-Login",
      secret
    );

    const recoveryCode = crypto.randomBytes(16).toString("hex");
    const qrCodeEncodedString = await QRCode.toDataURL(uri);

    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        isTwoFaEnabled: true,
        twoFaSecret: secret,
        twoFaRecoveryCode: recoveryCode,
      },
    });

    return {
      isEnabled: true,
      uri,
      recoveryCode,
      qrCodeEncodedString,
    };
  }

  async get2FAInfo(userId: string): Promise<ITwoFactorAuthInfo> {
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
      },
    });

    if (!user) {
      throw new NotFoundException("User not found");
    }
    let uri, qrCodeEncodedString;
    if (user.isTwoFaEnabled) {
      uri = await authenticator.keyuri(
        user.login,
        this.config.get("APP_NAME") ?? "NestJS-Login",
        user.twoFaSecret
      );
      qrCodeEncodedString = await QRCode.toDataURL(uri);
    }

    return {
      isEnabled: user.isTwoFaEnabled,
      uri: uri,
      recoveryCode: user.twoFaRecoveryCode,
      qrCodeEncodedString: qrCodeEncodedString,
    };
  }

  async toogle2FA(
    userId: string,
    isEnabled: boolean
  ): Promise<ITwoFactorAuthInfo> {
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
      },
    });

    if (!user) {
      throw new NotFoundException("User not found");
    }

    if (isEnabled) {
      if (user.isTwoFaEnabled) {
        throw new BadRequestException("2FA is already enabled");
      }
      if (user.twoFaSecret) {
        await this.prisma.user.update({
          where: {
            id: userId,
          },
          data: {
            isTwoFaEnabled: true,
          },
        });
        return await this.get2FAInfo(userId);
      } else {
        return await this.generate2FA(userId);
      }
    } else {
      if (!user.isTwoFaEnabled) {
        throw new BadRequestException("2FA is already disabled");
      }
      await this.prisma.user.update({
        where: {
          id: userId,
        },
        data: {
          isTwoFaEnabled: false,
        },
      });

      return { isEnabled: false };
    }
  }
}
