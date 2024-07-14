import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";
import { UserService } from "./user.service";
import { JwtStrategy } from "../common/jwt.strategy";
import { UserController } from "./user.controller";

@Module({
    imports: [
        PassportModule,
        JwtModule.register({
            secret: process.env.SECRET_KEY,
            signOptions: { expiresIn : '60m'}
        })
    ],
    providers: [UserService, JwtStrategy],
    controllers: [UserController]
})
export class UserModule {}