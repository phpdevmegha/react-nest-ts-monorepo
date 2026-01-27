"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProductsService = void 0;
const common_1 = require("@nestjs/common");
const product_repository_1 = require("./product.repository");
let ProductsService = class ProductsService {
    productRepo;
    constructor(productRepo) {
        this.productRepo = productRepo;
    }
    async findAll() {
        const products = await this.productRepo.findAllProducts();
        if (products.length === 0) {
            throw new common_1.NotFoundException('No products found');
        }
        return {
            success: true,
            message: 'Products fetched successfully',
            data: products,
        };
    }
    async findWithFilters(filters) {
        const { products, total } = await this.productRepo.findProductsWithFilters(filters);
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
    async findOne(id) {
        const product = await this.productRepo.findProductById(id);
        return {
            success: true,
            message: 'Product fetched successfully',
            data: product,
        };
    }
    async create(dto) {
        const product = await this.productRepo.createProduct(dto);
        return {
            success: true,
            message: 'Product created successfully',
            data: product,
        };
    }
    async update(id, dto) {
        const updated = await this.productRepo.updateProduct(id, dto);
        return {
            success: true,
            message: 'Product updated successfully',
            data: updated,
        };
    }
    async delete(id) {
        const deleted = await this.productRepo.deleteProduct(id);
        return {
            success: true,
            message: 'Product deleted successfully',
            data: deleted,
        };
    }
    async remove(id) {
        return this.delete(id);
    }
};
exports.ProductsService = ProductsService;
exports.ProductsService = ProductsService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [product_repository_1.ProductRepository])
], ProductsService);
//# sourceMappingURL=products.service.js.map