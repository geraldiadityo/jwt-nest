import { Body, Controller, Get, HttpCode, HttpException, Post, UseGuards } from "@nestjs/common";
import { UserService } from "./user.service";
import { LoginUserRequest, RegisterUserRequest, UserResponse } from "src/model/user.model";
import { WebResponse } from "../model/web.model";
import { Auth } from "../common/auth.decorator";
import { User } from "@prisma/client";
import { JwtAuthGuard } from "../common/jwt-auth.guard";
import { Throttle } from "@nestjs/throttler";

@Controller('/api/users')
export class UserController {
    constructor(
        private userService: UserService
    ) {}

    @Post()
    @HttpCode(201)
    async register(
        @Body() request: RegisterUserRequest
    ): Promise<WebResponse<UserResponse>> {
        const result = await this.userService.register(request);

        return {
            data: result
        }
    }

    @Post('/login')
    @HttpCode(200)
    async login(
        @Body() request: LoginUserRequest
    ): Promise<WebResponse<UserResponse>> {
        const user = await this.userService.validateUser(request);

        if(!user) {
            throw new HttpException('Invalid Credential', 401);
        }

        const result = await this.userService.login(user);
        
        return {
            data: result
        }
    }
    @Throttle({ default: {limit: 3, ttl: 5000} })
    @Get('/current')
    // @UseGuards(JwtAuthGuard)
    @HttpCode(200)
    async get(
        @Auth() user: User
    ): Promise<WebResponse<UserResponse>> {
        const result = await this.userService.get(user);
        return {
            data: result
        }
    }
}