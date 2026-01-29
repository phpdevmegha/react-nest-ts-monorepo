import { Injectable, NotFoundException } from '@nestjs/common';
import { ProductRepository } from './product.repository';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { Product } from './entities/product.entity';
import { ApiResponse } from 'src/common/response';
import { ProductFilterDto } from 'src/common/dto/pagination.dto';
import { PaginatedResponse } from 'src/common/PaginatedResponse';

@Injectable()
export class ProductsService {
  constructor(private readonly productRepo: ProductRepository) {}

  async findAll(): Promise<ApiResponse<Product[]>> {
    const products = await this.productRepo.findAllProducts();

    if (products.length === 0) {
      throw new NotFoundException('No products found');
    }

    return {
      success: true,
      message: 'Products fetched successfully',
      data: products,
    };
  }

  async findWithFilters(
    filters: ProductFilterDto,
  ): Promise<PaginatedResponse<Product>> {
    const { products, total } =
      await this.productRepo.findProductsWithFilters(filters);

    const page = filters.page || 1;
    const limit = filters.limit || 10;
    const totalPages = Math.ceil(total / limit);

    return {
      success: true,
      message: 'Products fetched successfully',
      data: products,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasMore: page < totalPages,
      },
    };
  }

  async findOne(id: number): Promise<ApiResponse<Product>> {
    const product = await this.productRepo.findProductById(id);

    return {
      success: true,
      message: 'Product fetched successfully',
      data: product,
    };
  }

  async create(dto: CreateProductDto): Promise<ApiResponse<Product>> {
    const product = await this.productRepo.createProduct(dto);

    return {
      success: true,
      message: 'Product created successfully',
      data: product,
    };
  }

  async update(
    id: number,
    dto: UpdateProductDto,
  ): Promise<ApiResponse<Product>> {
    const updated = await this.productRepo.updateProduct(id, dto);

    return {
      success: true,
      message: 'Product updated successfully',
      data: updated,
    };
  }

  async delete(id: number): Promise<ApiResponse<Product>> {
    const deleted = await this.productRepo.deleteProduct(id);

    return {
      success: true,
      message: 'Product deleted successfully',
      data: deleted,
    };
  }

  async remove(id: number): Promise<ApiResponse<Product>> {
    return this.delete(id);
  }
}
