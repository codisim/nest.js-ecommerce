import { Role } from '@prisma/client';
import { CategoryService } from './category.service';
import { RoleGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/role.decorators';
import { CreateCategoryDto } from './dto/create-category.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { CategoryResponseDto } from './dto/create-response.dto';
import { QueryCategoryDto } from './dto/query-category.dto';


@ApiTags('categories')
@Controller('category')
export class CategoryController {
    constructor(private readonly categoryService: CategoryService) { }

    // create a category
    @Post()
    @UseGuards(JwtAuthGuard, RoleGuard)
    @Roles(Role.ADMIN)
    @ApiBearerAuth('JWT-auth')
    @ApiOperation({ summary: "Create a new category" })
    @ApiBody({ type: CreateCategoryDto })
    async createCategory(@Body() createCategory: CreateCategoryDto): Promise<CategoryResponseDto> {
        return await this.categoryService.createCategory(createCategory);
    }

    // get all categories
    @Get()
    @ApiOperation({ summary: 'Get all categories' })
    @ApiResponse({
        status: 200,
        description: 'Get all categories successfully.....!',
        schema: {
            type: 'object',
            properties: {
                data: {
                    type: 'array',
                    items: { $ref: '#/components/schemas/CategoryResponseDto' }
                },
                meta: {
                    type: 'object',
                    properties: {
                        total: { type: 'number' },
                        page: { type: 'number' },
                        limit: { type: 'number' },
                        totalPages: { type: 'number' }
                    }
                }
            }
        }
    })

    async findAll(@Query() queryDto: QueryCategoryDto) {
        return await this.categoryService.findAll(queryDto);
    }
}
