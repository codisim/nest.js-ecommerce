import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { RefreshTokenGuard } from './guards/refresh-token-guard';
import { GetUser } from 'src/common/decorators/get-user.decorator';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { LoginDto } from './dto/login.dto';
import { ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';

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
    @ApiBearerAuth('refresh-token')
    @ApiOperation({
        summary: 'Refresh access token',
        description: 'Refresh access token using refresh token. Access token must be expired or about to expire'
    })

    @ApiResponse({
        status: 200,
        description: 'Access token refreshed successfully',
        type: AuthResponseDto
    })

    @ApiResponse({
        status: 401,
        description: 'Unauthorized. Invalid or expired refresh token',
    })

    @ApiResponse({
        status: 500,
        description: 'Internal server error',
    })


    async refresh(@GetUser('id') userId: string): Promise<AuthResponseDto> {
        return await this.authService.refreshTokens(userId);
    }

    // logout use and invalid refresh token
    @Post('logout')
    @HttpCode(HttpStatus.OK)
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth('JWT-auth')
    @ApiOperation({
        summary: 'Logout user',
        description: 'Logout user and invalidate refresh token. Access token must be valid'
    })

    @ApiResponse({
        status: 200,
        description: 'Logged out successfully',
    })

    @ApiResponse({
        status: 401,
        description: 'Unauthorized. Invalid or expired access token',
    })
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
