import { PassportStrategy } from "@nestjs/passport";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { AuthService } from "../auth.service";
import { ExtractJwt, Strategy } from "passport-jwt";
import { ConfigService } from "@nestjs/config";
import { IJwtPayload, IUserSafe } from "../auth";

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

  async validate(jwtPayload: IJwtPayload): Promise<IUserSafe> {
    const user = await this.authService.validateUser(jwtPayload);
    if (!user) {
      throw new UnauthorizedException();
    }

    if (!jwtPayload.authenticated) {
      throw new UnauthorizedException("User is not authenticated (2FA)");
    }

    return user;
  }
}
