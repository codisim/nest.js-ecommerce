import { ApiProperty } from "@nestjs/swagger";
import { Role } from "@prisma/client";


export class AuthResponseDto {

    @ApiProperty({
        description: 'Access token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    })
    accessToken: string;

    @ApiProperty({
        description: 'Refresh token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw'
    })
    refreshToken: string;

    @ApiProperty({
        description: 'User object',
        example: {
            id: '123e4567-e89b-12d3-a456-426617554400',
            email: 'john.doe@example.com',
            firstName: 'John',
            lastName: 'Doe',
            role: 'USER'
        }
    })
    user: {
        id: string;
        email: string;
        firstName: string | null;
        lastName: string | null;
        role: Role
    }
}