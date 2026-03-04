import { ApiProperty } from "@nestjs/swagger";
import { Role } from "@prisma/client";


export class UserResponseDto {
    @ApiProperty({
        description: 'The unique identifier of the user',
        example: '123e4567-e89b-12d3-a456-426614174000'
    })
    id: string;


    @ApiProperty({
        description: 'The email address of the user',
        example: 'john.doe@example.com'
    })
    email: string;

    @ApiProperty({
        description: 'The first name of the user',
        example: 'John'
    })
    firstName: string;

    @ApiProperty({
        description: 'The last name of the user',
        example: 'Doe',
        nullable: true
    })
    lastName: string | null;

    @ApiProperty({
        description: 'The roles assigned to the user',
        enum: Role
    })
    role: Role;

    @ApiProperty({
        description: 'The date and time when the user was created',
        example: '2024-01-01T00:00:00.000Z'
    })
    createdAt: Date;

    @ApiProperty({
        description: 'The date and time when the user was last updated',
        example: '2024-01-01T00:00:00.000Z'
    })
    updatedAt: Date;

}