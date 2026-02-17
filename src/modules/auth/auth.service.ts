import { ConflictException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    private readonly SALT_ROUNDS = 12;
    constructor(private prisma: PrismaService, private readonly jwtService: JwtService) { }

    async register(registerDto: RegisterDto): Promise<AuthResponseDto> {
        const { email, password, firstName, lastName } = registerDto;

        const existingUser = this.prisma.user.findUnique({
            where: {
                email
            }
        })

        if (existingUser)
            throw new ConflictException('User already exists')

        const hashedPassword = await bcrypt.hash(password, this.SALT_ROUNDS);

        const user = await this.prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                firstName,
                lastName
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


    }





    // generate access and refresh token
    private async generateTokens(userId: string, email: string): Promise<{ accessToken: string, refreshToken: string }> {
        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync({
                sub: userId,
                email
            })
        ])
    }




}
