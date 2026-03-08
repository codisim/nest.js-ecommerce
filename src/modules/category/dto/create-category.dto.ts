import { ApiProperty } from "@nestjs/swagger";
import { IsBoolean, IsNotEmpty, IsOptional, IsString, MaxLength } from "class-validator";


export class CreateCategoryDto {

    @ApiProperty({
        example: 'Food',
        description: 'The name of category',
        maxLength: 120
    })
    @IsString()
    @IsNotEmpty()
    @MaxLength(120)
    name: string;


    @ApiProperty({
        example: 'Rice',
        description: 'A short descriptopn of the category',
        required: false,
        maxLength: 255
    })
    @IsString()
    @IsOptional()
    @MaxLength(255)
    description?: string;


    @ApiProperty({
        example: 'Food',
        description: 'The URL friendly slug for category',
        required: false,
        maxLength: 120
    })
    @IsString()
    @IsOptional()
    @MaxLength(120)
    slug?: string;


    @ApiProperty({
        example: 'https://example.com/images/124.png',
        description: 'URL of the category image',
        required: false,
        maxLength: 255
    })
    @IsString()
    @IsOptional()
    @MaxLength(255)
    imageUrl: string;


    @ApiProperty({
        example: true,
        description: 'Indicates if the category is active',
        required: false,
        default: true
    })
    @IsBoolean()
    @IsOptional()
    isActice?: boolean
}