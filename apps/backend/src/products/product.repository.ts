import { Injectable, NotFoundException } from '@nestjs/common';
import { DataSource, Repository, Between, Like, ILike } from 'typeorm';
import { Product } from './entities/product.entity';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { ProductFilterDto } from 'src/common/dto/pagination.dto';

@Injectable()
export class ProductRepository extends Repository<Product> {
  constructor(private dataSource: DataSource) {
    super(Product, dataSource.createEntityManager());
  }

  async findAllProducts(): Promise<Product[]> {
    return this.find();
  }

  async findProductsWithFilters(
    filters: ProductFilterDto,
  ): Promise<{ products: Product[]; total: number }> {
    const query = this.createQueryBuilder('product');

    // Search by title
    if (filters.search) {
      query.where('product.title ILIKE :search', {
        search: `%${filters.search}%`,
      });
    }

    // Filter by price range
    if (filters.minPrice !== undefined && filters.maxPrice !== undefined) {
      query.andWhere('product.price BETWEEN :minPrice AND :maxPrice', {
        minPrice: filters.minPrice,
        maxPrice: filters.maxPrice,
      });
    } else if (filters.minPrice !== undefined) {
      query.andWhere('product.price >= :minPrice', {
        minPrice: filters.minPrice,
      });
    } else if (filters.maxPrice !== undefined) {
      query.andWhere('product.price <= :maxPrice', {
        maxPrice: filters.maxPrice,
      });
    }

    // Get total count before pagination
    const total = await query.getCount();

    // Sort
    const sortField = filters.sortBy === 'price' ? 'product.price' : 'product.title';
    const order = filters.order || 'DESC';
    query.orderBy(sortField, order as 'ASC' | 'DESC');

    // Pagination
    const skip = ((filters.page || 1) - 1) * (filters.limit || 10);
    query.skip(skip).take(filters.limit || 10);

    const products = await query.getMany();
    return { products, total };
  }

  async findProductById(id: number): Promise<Product> {
    const product = await this.findOne({ where: { id } });
    if (!product) {
      throw new NotFoundException('Product Not Found');
    }
    return product;
  }

  async createProduct(dto: CreateProductDto): Promise<Product> {
    const product = this.create(dto);
    return this.save(product);
  }

  async updateProduct(id: number, dto: UpdateProductDto): Promise<Product> {
    const product = await this.findProductById(id);
    Object.assign(product, dto);
    return this.save(product);
  }

  async deleteProduct(id: number): Promise<Product> {
    const product = await this.findProductById(id);
    await this.remove(product);
    return product;
  }
}
