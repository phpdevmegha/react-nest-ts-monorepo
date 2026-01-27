import { DataSource, Repository } from 'typeorm';
import { Product } from './entities/product.entity';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { ProductFilterDto } from 'src/common/dto/pagination.dto';
export declare class ProductRepository extends Repository<Product> {
    private dataSource;
    constructor(dataSource: DataSource);
    findAllProducts(): Promise<Product[]>;
    findProductsWithFilters(filters: ProductFilterDto): Promise<{
        products: Product[];
        total: number;
    }>;
    findProductById(id: number): Promise<Product>;
    createProduct(dto: CreateProductDto): Promise<Product>;
    updateProduct(id: number, dto: UpdateProductDto): Promise<Product>;
    deleteProduct(id: number): Promise<Product>;
}
