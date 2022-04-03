import { PassportStrategy } from "@nestjs/passport";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { AuthService, JwtPayload } from "../auth.service";
import { User } from "@prisma/client";
import { ExtractJwt, Strategy } from "passport-jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, "local") {
  constructor(private authService: AuthService, private config: ConfigService) {
    super({
      jwtFromRequest: (req) => {
        const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
        if (token) {
          return token;
        }
        const cookies = req.cookies;
        if (cookies && cookies.accessToken) {
          return cookies.accessToken;
        }
        return null;
      },
      secretOrKey: config.get("JWT_ACCESS_SECRET"),
    });
  }

  async validate(jwtPayload: JwtPayload): Promise<User> {
    const user = await this.authService.validateUser(jwtPayload);
    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
  }
}
