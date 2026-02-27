import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { RefreshTokenGuard } from './guards/refresh-token-guard';
import { GetUser } from 'src/common/decorators/get-user.decorator';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { LoginDto } from './dto/login.dto';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    // register API
    @Post('register')
    @HttpCode(201)
    @ApiOperation({ summary: 'Register a new user', description: 'Register a new user with email and password' })
    @ApiResponse({
        status: 201,
        description: 'User registered successfully',
        type: AuthResponseDto
    })

    @ApiResponse({
        status: 400,
        description: 'Bad request',
    })

    @ApiResponse({
        status: 409,
        description: 'User already exists',
    })

    @ApiResponse({
        status: 500,
        description: 'Internal server error',
    })

    @ApiResponse({
        status: 429,
        description: 'Too many request. Rate limit exceeded'
    })

    async register(@Body() registerDto: RegisterDto): Promise<AuthResponseDto> {
        return this.authService.register(registerDto);
    }


    // refresh access token
    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    @UseGuards(RefreshTokenGuard)
    async refresh(@GetUser('id') userId: string): Promise<AuthResponseDto> {
        return await this.authService.refreshTokens(userId);
    }

    // logout use and invalid refresh token
    @Post('logout')
    @HttpCode(HttpStatus.OK)
    @UseGuards(JwtAuthGuard)
    async logout(@GetUser('id') userId: string): Promise<{ message: string }> {
        await this.authService.logout(userId);
        return {
            message: 'Logged out successfully'
        }
    }


    // login
    @Post('login')
    @HttpCode(HttpStatus.OK)
    async login(@Body() loginDto: LoginDto): Promise<AuthResponseDto> {
        return await this.authService.login(loginDto);
    }

}
