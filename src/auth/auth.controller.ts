import { Body, Controller, Post } from "@nestjs/common";
import { User } from "@prisma/client";
import { AuthService } from "./auth.service";
import { UserDto } from "./dto/user.dto";

@Controller("auth")
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post("/addUser")
  async addUser(
    @Body() user: UserDto
  ): Promise<{ user: User; accessToken: string }> {
    return await this.authService.addUser(user);
  }
}
