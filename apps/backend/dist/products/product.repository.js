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
exports.ProductRepository = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("typeorm");
const product_entity_1 = require("./entities/product.entity");
let ProductRepository = class ProductRepository extends typeorm_1.Repository {
    dataSource;
    constructor(dataSource) {
        super(product_entity_1.Product, dataSource.createEntityManager());
        this.dataSource = dataSource;
    }
    async findAllProducts() {
        return this.find();
    }
    async findProductsWithFilters(filters) {
        const query = this.createQueryBuilder('product');
        if (filters.search) {
            query.where('product.title ILIKE :search', {
                search: `%${filters.search}%`,
            });
        }
        if (filters.minPrice !== undefined && filters.maxPrice !== undefined) {
            query.andWhere('product.price BETWEEN :minPrice AND :maxPrice', {
                minPrice: filters.minPrice,
                maxPrice: filters.maxPrice,
            });
        }
        else if (filters.minPrice !== undefined) {
            query.andWhere('product.price >= :minPrice', {
                minPrice: filters.minPrice,
            });
        }
        else if (filters.maxPrice !== undefined) {
            query.andWhere('product.price <= :maxPrice', {
                maxPrice: filters.maxPrice,
            });
        }
        const total = await query.getCount();
        const sortField = filters.sortBy === 'price' ? 'product.price' : 'product.title';
        const order = filters.order || 'DESC';
        query.orderBy(sortField, order);
        const skip = ((filters.page || 1) - 1) * (filters.limit || 10);
        query.skip(skip).take(filters.limit || 10);
        const products = await query.getMany();
        return { products, total };
    }
    async findProductById(id) {
        const product = await this.findOne({ where: { id } });
        if (!product) {
            throw new common_1.NotFoundException('Product Not Found');
        }
        return product;
    }
    async createProduct(dto) {
        const product = this.create(dto);
        return this.save(product);
    }
    async updateProduct(id, dto) {
        const product = await this.findProductById(id);
        Object.assign(product, dto);
        return this.save(product);
    }
    async deleteProduct(id) {
        const product = await this.findProductById(id);
        await this.remove(product);
        return product;
    }
};
exports.ProductRepository = ProductRepository;
exports.ProductRepository = ProductRepository = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeorm_1.DataSource])
], ProductRepository);
//# sourceMappingURL=product.repository.js.map