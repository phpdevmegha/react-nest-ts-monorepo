import { ProductsService } from './products.service';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { ProductFilterDto } from 'src/common/dto/pagination.dto';
export declare class ProductsController {
    private readonly productsService;
    constructor(productsService: ProductsService);
    create(dto: CreateProductDto): Promise<import("../common/response").ApiResponse<import("./entities/product.entity").Product>>;
    findAll(filters: ProductFilterDto): Promise<import("../common/response").ApiResponse<import("./entities/product.entity").Product[]>>;
    findOne(id: number): Promise<import("../common/response").ApiResponse<import("./entities/product.entity").Product>>;
    update(id: number, dto: UpdateProductDto): Promise<import("../common/response").ApiResponse<import("./entities/product.entity").Product>>;
    remove(id: number): Promise<import("../common/response").ApiResponse<import("./entities/product.entity").Product>>;
}
