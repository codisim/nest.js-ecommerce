import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { PrismaService } from "src/prisma/prisma.service";
// import { Strategy } from "passport-jwt";



@Injectable
export class JwtStrategy extends PassportStrategy(Strategy){
    constructor(
        private prisma: PrismaService,
        private configService: ConfigService
    ){

    }
}