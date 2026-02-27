import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsOptional, IsString, MinLength } from "class-validator";


export class RegisterDto {

    @ApiProperty({
        description: 'Email address of the user',
        example: 'john.doe@example.com',
    })
    @IsEmail({}, { message: 'Please provide a valid email address.' })
    @IsNotEmpty({ message: 'Email cannot be empty.' })
    email: string;

    @ApiProperty({
        description: 'Password of the user',
        example: 'password123',
    })
    @IsNotEmpty({ message: 'Password cannot be empty.' })
    @IsString()
    @MinLength(6, { message: 'Password must be at least 6 characters long.' })
    password: string;

    @IsNotEmpty({ message: 'First name cannot be empty.' })
    @IsString()
    firstName: string;

    @IsOptional()
    @IsString()
    lastName?: string;

}