import { Injectable, NotFoundException, Search } from '@nestjs/common';
import { Category, Prisma, PrismaClient } from '@prisma/client';
import { CreateCategoryDto } from './dto/create-category.dto';
import { CategoryResponseDto } from './dto/create-response.dto';
import { QueryCategoryDto } from './dto/query-category.dto';
import { UpdateCategoryDto } from './dto/update-category.dto';

@Injectable()
export class CategoryService {
    constructor(private prisma: PrismaClient) { }

    async createCategory(createCategoryDto: CreateCategoryDto): Promise<CategoryResponseDto> {
        const { name, slug, ...rest } = createCategoryDto;

        const categorySlug = slug ? name.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]/g, '') : '';

        const existingCategory = await this.prisma.category.findUnique({
            where: { slug: categorySlug }
        })

        if (existingCategory)
            throw new Error(categorySlug + "is already exist...!");

        const category = await this.prisma.category.create({
            data: {
                name,
                slug: categorySlug,
                ...rest
            },
        });

        return this.formatCategory(category, 0);
    }


    async findAll(queryDto: QueryCategoryDto): Promise<{
        data: CategoryResponseDto[],
        meta: {
            total: number,
            page: number,
            limit: number,
            totalPages: number,
        }
    }> {

        const { isActive, search, page = 1, limit = 10 } = queryDto;

        const where: Prisma.CategoryWhereInput = {};

        if (isActive !== undefined) {
            where.isActice = isActive;
        }

        if (search) {
            where.OR = [
                {
                    name: { contains: search, mode: 'insensitive' }
                },
                {
                    description: { contains: search, mode: 'insensitive' }
                },
            ];
        }

        const total = await this.prisma.category.count({ where });
        const cotegories = await this.prisma.category.findMany({
            where,
            skip: (page - 1) * limit,
            take: limit,
            orderBy: { createdAt: 'desc' },
            include: {
                _count: {
                    select: {
                        product: true
                    },
                },
            },
        });

        return {
            data: cotegories.map((category) =>
                this.formatCategory(category, category._count.product),
            ),
            meta: {
                total,
                page,
                limit,
                totalPages: Math.ceil(total / limit)
            }
        }

    }


    private formatCategory(category: Category, productCount: number): any {
        return {
            id: category.id,
            productCount,
            name: category.name,
            description: category.description,
            imageUrl: category.imageUrl,
            isActice: category.isActice,
            createdAt: category.createdAt,
            updatedAt: category.updatedAt
        }
    }

    // get category by id

    async findById(id: string): Promise<CategoryResponseDto> {
        const category = await this.prisma.category.findUnique({
            where: { id },
            include: {
                _count: {
                    select: {
                        product: true
                    },
                },
            },
        });

        if (!category) {
            throw new NotFoundException('Category not found');
        }

        return this.formatCategory(category, Number(category._count.product));
    }

    // update category by id (admin only)

    async updateById(id: string, updateCategoryDto: UpdateCategoryDto): Promise<CategoryResponseDto> {

        const existingCategory = await this.prisma.category.findUnique({
            where: { id }
        });

        if (!existingCategory) {
            throw new NotFoundException('Category not found');
        }


        if (updateCategoryDto.slug && updateCategoryDto.slug !== existingCategory.slug) {
            const existingCategoryWithSameSlug = await this.prisma.category.findUnique({
                where: { slug: updateCategoryDto.slug }
            });

            if (existingCategoryWithSameSlug) {
                throw new Error(updateCategoryDto.slug + " is already exist...!");
            }
        }

        const updatedCategory = await this.prisma.category.update({
            where: { id },
            data: {
                ...updateCategoryDto,
                updatedAt: new Date(),
            },
            include: {
                _count: {
                    select: {
                        product: true
                    },
                },
            },
        });

        return this.formatCategory(updatedCategory, Number(updatedCategory._count.product));
    }
}