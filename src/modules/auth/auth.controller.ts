import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { RefreshTokenGuard } from './guards/refresh-token-guard';
import { GetUser } from 'src/common/decorators/get-user.decorator';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    // register API
    @Post('register')
    async register(@Body() registerDto: RegisterDto): Promise<AuthResponseDto> {
        return this.authService.register(registerDto);
    }


    // refresh access token
    @Post('refresh')
    @UseGuards(RefreshTokenGuard)
    async refresh(@GetUser('id') userId: string): Promise<AuthResponseDto> {
        return await this.authService.refreshTokens(userId);
    }

    // logout use and invalid refresh token
    @Post('logout')
    @UseGuards(JwtAuthGuard)
    async logout(@GetUser('id') userId: string): Promise<{ message: string }> {
        await this.authService.logout(userId);
        return {
            message: 'Logged out successfully'
        }
    }


    // login
    @Post('login')
    async login(@Body() loginDto: LoginDto): Promise<AuthResponseDto>{
        return await this.authService.login(loginDto);
    }

}
