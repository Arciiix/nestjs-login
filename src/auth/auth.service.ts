import { ConflictException, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { User } from "@prisma/client";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import * as argon from "argon2";
import { PrismaService } from "src/prisma/prisma.service";
import { UserDto } from "./dto/user.dto";

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService
  ) {}

  async addUser(user: UserDto): Promise<{ user: User; accessToken: string }> {
    try {
      const hash = await argon.hash(user.password);

      const userObj: User = await this.prisma.user.create({
        data: { ...user, ...{ password: hash } },
      });

      userObj.password = null; //Don't send the password hash back to user

      return {
        user: userObj,
        accessToken: await this.generateAccessTokenForUser(userObj),
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

  generateAccessTokenForUser(user: User): Promise<string> {
    const data = {
      id: user.id,
      login: user.login,
    };

    return this.jwt.signAsync(data, {
      expiresIn: "15m",
      secret: this.config.get("JWT_SECRET"),
    });
  }
}
