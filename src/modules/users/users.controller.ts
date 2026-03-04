import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RoleGuard } from 'src/common/guards/roles.guard';
import { UsersService } from './users.service';
import { UserResponseDto } from './dto/user-response.dto';
import type { RequestWithUser } from 'src/common/interfaces/request-with-user.interface';
import { Roles } from 'src/common/decorators/role.decorators';
import { Role } from '@prisma/client';



@ApiTags('users')
@ApiBearerAuth('JWT-auth')
@UseGuards(JwtAuthGuard, RoleGuard)

@Controller('users')
export class UsersController {
    constructor(private readonly userService: UsersService) { }

    // get current user profile
    @Get('me')
    @ApiOperation({ summary: 'Get current user profile' })
    @ApiResponse({
        status: 200,
        description: 'The user profile has been successfully retrieved.',
        type: UserResponseDto
    })

    @ApiResponse({
        status: 401,
        description: 'Unauthorized. The user is not authenticated or the token is invalid.'
    })

    async getProfile(@Req() req: RequestWithUser): Promise<UserResponseDto> {
        return await this.userService.getProfile(req.user.id);
    }

    // get all users (admin only)
    @Get()
    @Roles(Role.ADMIN)
    @ApiOperation({ summary: 'Get all users (admin only)' })
    @ApiResponse({
        status: 200,
        description: 'A list of all users has been successfully retrieved.',
        type: [UserResponseDto]
    })

    @ApiResponse({
        status: 401,
        description: 'Unauthorized. The user is not authenticated or the token is invalid.'
    })

    @ApiResponse({
        status: 403,
        description: 'Forbidden. The user does not have the required permissions to access this resource.'
    })

    async getAllUsers(): Promise<UserResponseDto[]> {
        return await this.userService.getAllUsers();
    }

    // get user by id (admin only)
    @Get(':id')
    @Roles(Role.ADMIN)
    @ApiOperation({ summary: 'Get user by id (admin only)' })
    @ApiResponse({
        status: 200,
        description: 'The user has been successfully retrieved.',
        type: UserResponseDto
    })

    @ApiResponse({
        status: 401,
        description: 'Unauthorized. The user is not authenticated or the token is invalid.'
    })

    @ApiResponse({
        status: 403,
        description: 'Forbidden. The user does not have the required permissions to access this resource.'
    })

    async getUserById(@Param('id') id: string): Promise<UserResponseDto> {
        return await this.userService.getUserById(id);
    }

}