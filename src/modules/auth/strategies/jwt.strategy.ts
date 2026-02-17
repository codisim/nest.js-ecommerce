import { Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { PrismaService } from "src/prisma/prisma.service";
import { Strategy, ExtractJwt } from "passport-jwt";



@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        private prisma: PrismaService,
        private configService: ConfigService
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: configService.get<string>('JWT_SECRET'),
            ignoreExpiration: false
        })
    }


    // validate JWT payload
    async validate(payload: { sub: string, email: string }) {
        const user = await this.prisma.user.findUnique({
            where: {
                id: payload.sub
            },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                role: true,
                password: false
            }
        })

        if (!user)
            throw new UnauthorizedException('User not found')

        return user;
    }

}