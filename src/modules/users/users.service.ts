import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UserResponseDto } from './dto/user-response.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
    constructor(private prisma: PrismaService) { }

    async getProfile(userId: string): Promise<UserResponseDto> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                role: true,
                createdAt: true,
                updatedAt: true,
                password: false
            }
        })

        if (!user)
            throw new NotFoundException('User not found');

        return user
    }


    // get all users (admin only)
    async getAllUsers(): Promise<UserResponseDto[]> {
        const users = await this.prisma.user.findMany({
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                role: true,
                createdAt: true,
                updatedAt: true,
                password: false
            },
            orderBy: {
                createdAt: 'desc'
            }
        })

        return users;
    }

    // get user by id (admin only)
    async getUserById(id: string): Promise<UserResponseDto> {
        const user = await this.prisma.user.findUnique({
            where: { id },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                role: true,
                createdAt: true,
                updatedAt: true,
                password: false
            }
        })

        if (!user)
            throw new NotFoundException('User not found');

        return user
    }

    // update user profile (current user)
    async updateProfile(userId: string, updateUserDto: UpdateUserDto): Promise<UserResponseDto> {
        const user = await this.prisma.user.update({
            where: { id: userId },
            data: {
                email: updateUserDto.email,
                firstName: updateUserDto.firstName,
                lastName: updateUserDto.lastName
            },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                role: true,
                createdAt: true,
                updatedAt: true,
                password: false
            }
        })

        return user;
    }


    // change password (current user)
    async changePassword(userId: string, changePasswordDto: ChangePasswordDto): Promise<{ message: string }> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId }
        })

        if (!user)
            throw new NotFoundException('User not found');

        // check if current password is correct
        if (user.password !== changePasswordDto.currentPassword)
            throw new NotFoundException('Current password is incorrect');

        const isSamed = user.password === changePasswordDto.newPassword;
        if (isSamed)
            throw new NotFoundException('New password cannot be the same as current password');

        const hashedPassword = await bcrypt.hash(changePasswordDto.newPassword, 10);

        await this.prisma.user.update({
            where: { id: userId },
            data: {
                password: hashedPassword
            }
        })
        return { message: 'Password changed successfully' };
    }


}
