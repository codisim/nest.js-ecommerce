import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty } from "class-validator";

export class ChangePasswordDto {
    @ApiProperty({
        description: 'The current password of the user',
        example: 'currentPassword123'
    })
    @IsNotEmpty()
    currentPassword: string;

    @ApiProperty({
        description: 'The new password of the user',
        example: 'newPassword123'
    })
    @IsNotEmpty()
    newPassword: string;
}   