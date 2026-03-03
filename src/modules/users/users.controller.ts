import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RoleGuard } from 'src/common/guards/roles.guard';
import { UsersService } from './users.service';



@ApiTags('users')
@ApiBearerAuth('JWT-auth')
@UseGuards(JwtAuthGuard, RoleGuard)

@Controller('users')


export class UsersController {
    constructor(private readonly userService: UsersService) {}

    // get current user profile
    @Get('me')
    @ApiOperation({ summary: 'Get current user profile' })
    @ApiResponse({ 
        status: 200, 
        description: 'The user profile has been successfully retrieved.',
        type: UserResponseDto
    })
}
