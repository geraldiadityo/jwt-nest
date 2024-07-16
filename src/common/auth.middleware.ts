import { HttpException, Inject, Injectable, NestMiddleware } from "@nestjs/common";
import * as jwt from 'jsonwebtoken';
import { WINSTON_MODULE_PROVIDER } from "nest-winston";
import { Logger } from "winston";
import { PrismaService } from "./prisma.service";
@Injectable()
export class AuthMiddleware implements NestMiddleware {
    constructor(
        @Inject(WINSTON_MODULE_PROVIDER)private readonly logger: Logger,
        private prismaService: PrismaService
    ) {}
    async use(req: any, res: any, next: (error?: Error | any) => void) {
        const token = req.headers['authorization']?.split(' ')[1];
        
        if(!token){
            throw new HttpException('Token invalid', 401);
        }

        try {
            const decoded = jwt.verify(token, process.env.SECRET_KEY) as { username: string }
            // req.user = decoded.username;
            // this.logger.info(process.env.SECRET_KEY);
            const user = await this.prismaService.user.findUnique({
                where: {
                    username: decoded.username as string
                }
            });

            req.user = user;
            next()
        } catch (error){
            throw new HttpException('Invalid JWT', 401);
        }
    }
}