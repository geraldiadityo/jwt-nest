import { HttpException, Inject, Injectable } from "@nestjs/common";
import { ValidationService } from "../common/validation.service";
import { WINSTON_MODULE_PROVIDER } from "nest-winston";
import { Logger } from "winston";
import { PrismaService } from "../common/prisma.service";

import * as bcrypt from 'bcrypt';
import { LoginUserRequest, RegisterUserRequest, UserResponse } from "../model/user.model";
import { UserValidation } from "./user.validation";
import { JwtService } from "@nestjs/jwt";
import { User } from "@prisma/client";

@Injectable()
export class UserService {
    constructor(
        private validatioService: ValidationService,
        @Inject(WINSTON_MODULE_PROVIDER) private logger: Logger,
        private prismaService: PrismaService,
        private jwtService: JwtService
    ) {}

    async register(
        request: RegisterUserRequest
    ): Promise<UserResponse> {
        this.logger.debug(`Register new User ${JSON.stringify(request)}`);

        const registerRequest = this.validatioService.validate(UserValidation.REGISTER, request);

        const totalUserWithSameUsername = await this.prismaService.user.count({
            where: {
                username: registerRequest.username
            }
        });

        if(totalUserWithSameUsername != 0){
            throw new HttpException('Username Already Exists', 400);
        }

        registerRequest.password = await bcrypt.hash(registerRequest.password, 10);

        const user = await this.prismaService.user.create({
            data: registerRequest
        });

        return {
            username: user.username,
            name: user.name
        }
    }

    async validateUser(
        request: LoginUserRequest
    ): Promise<User> {
        this.logger.debug(`user service login : ${JSON.stringify(request)}`);
        const loginRequest = this.validatioService.validate(UserValidation.LOGIN, request);
        
        const user = await this.prismaService.user.findUnique({
            where: {
                username: loginRequest.username
            }
        });

        if(!user){
            throw new HttpException('Username or password is invalid', 401);
        }

        if(!(user && bcrypt.compareSync(loginRequest.password, user.password))){
            throw new HttpException('Username Or password is invalid', 401);
        }

        return {
            username: user.username,
            name: user.name,
            password: user.password
        }
    };

    async login(user: User): Promise<UserResponse>{
        const payload = { username: user.username, sub:user.name };
        return {
            username: user.username,
            name: user.name,
            token: this.jwtService.sign(payload)
        }
    }

    async get(
        user: User
    ): Promise<UserResponse> {
        return {
            username: user.username,
            name: user.name
        }
    }
}