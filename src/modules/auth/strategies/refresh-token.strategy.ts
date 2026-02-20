import { Request } from "express";
import { ConfigService } from "@nestjs/config";
import { Strategy, ExtractJwt } from "passport-jwt";
import { PassportStrategy } from "@nestjs/passport";
import { PrismaService } from "src/prisma/prisma.service";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from 'bcrypt';



@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
    constructor(
        private prisma: PrismaService,
        private configService: ConfigService
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: configService.get<string>('REFRSH_TOKEN_SECRET'),
            ignoreExpiration: false,
            passReqToCallback: true
        });
    }

    async validate(req: Request, payload: { sub: string, email: string }) {
        console.log('RefreshTokenStrategy.validate called');
        console.log('Payload', { sub: payload.sub, email: payload.email });

        const authHeader = req.headers.authorization;
        if (!authHeader)
            throw new UnauthorizedException("Refresh token not found");

        const refreshToken = authHeader.replace('Bearer', '').trim();

        if (!refreshToken)
            throw new UnauthorizedException("Refresh token is empty after extrating");

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
                refreshToken: true
            }
        });


        if (!user || !user.refreshToken)
            throw new UnauthorizedException("User not found or refresh token not found");

        const refreshTokenMatched = await bcrypt.compare(refreshToken, user.refreshToken);

        if (!refreshTokenMatched)
            throw new UnauthorizedException("Refresh token does not match");

        return {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            role: user.role,
            refreshToken: user.refreshToken
        }

    }

}