import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsOptional, IsString } from "class-validator";


export class UpdateUserDto {
    @ApiProperty({
        description: 'The email address of the user',
        example: 'john.doe@example.com'
    })
    @IsEmail()
    @IsOptional()
    email?: string;

    @ApiProperty({
        description: 'The first name of the user',
        example: 'John'
    })
    @IsString()
    @IsOptional()
    firstName?: string;

    @ApiProperty({
        description: 'The last name of the user',
        example: 'Doe',
        nullable: true
    })
    @IsString()
    @IsOptional()
    lastName?: string | null;
}   