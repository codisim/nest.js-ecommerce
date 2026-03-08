import { ApiProperty } from "@nestjs/swagger";

export class CategoryResponseDto {
    @ApiProperty({
        example: '123e4567-e89b-12d3-a456-426617554400',
        description: 'The unique identifier of the category'
    })
    id: string

    @ApiProperty({
        example: 'Food',
        description: 'The name of category',
    })
    name: string

    @ApiProperty({
        example: 'Rice',
        description: 'A short descriptopn of the category',
        nullable: true
    })
    description: string | null;


    @ApiProperty({
        example: 'Food',
        description: 'The URL friendly slug for category',
        nullable: true
    })
    slug: string | null;


    @ApiProperty({
        example: 'https://example.com/images/124.png',
        description: 'URL of the category image',
        nullable: true
    })
    imageUrl: string | null;


    @ApiProperty({
        example: true,
        description: 'Indicates if the category is active',
    })
    isActice: boolean


    @ApiProperty({
        example: 150,
        description: 'Numbers of products in this category',
    })
    productCount: number


    createdAt: Date
    updatedAt: Date


}