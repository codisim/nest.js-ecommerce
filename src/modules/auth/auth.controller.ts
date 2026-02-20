import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { Body, Controller, UseGuards } from '@nestjs/common';
import { RefreshTokenGuard } from './guards/refresh-token-guard';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    async register(@Body() registerDto: RegisterDto): Promise<AuthResponseDto> {
        return this.authService.register(registerDto);
    }


    @UseGuards(RefreshTokenGuard)
    async refresh() {

    }


}
