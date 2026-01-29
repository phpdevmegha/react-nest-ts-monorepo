import { ProductRepository } from './product.repository';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { Product } from './entities/product.entity';
import { ApiResponse } from 'src/common/response';
import { ProductFilterDto } from 'src/common/dto/pagination.dto';
import { PaginatedResponse } from 'src/common/PaginatedResponse';
export declare class ProductsService {
    private readonly productRepo;
    constructor(productRepo: ProductRepository);
    findAll(): Promise<ApiResponse<Product[]>>;
    findWithFilters(filters: ProductFilterDto): Promise<PaginatedResponse<Product>>;
    findOne(id: number): Promise<ApiResponse<Product>>;
    create(dto: CreateProductDto): Promise<ApiResponse<Product>>;
    update(id: number, dto: UpdateProductDto): Promise<ApiResponse<Product>>;
    delete(id: number): Promise<ApiResponse<Product>>;
    remove(id: number): Promise<ApiResponse<Product>>;
}
