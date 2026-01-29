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
exports.OrderRepository = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("typeorm");
const order_entity_1 = require("./entities/order.entity");
const user_entity_1 = require("../users/entities/user.entity");
const product_entity_1 = require("../products/entities/product.entity");
const order_status_enum_1 = require("./enum/order-status.enum");
let OrderRepository = class OrderRepository extends typeorm_1.Repository {
    dataSource;
    constructor(dataSource) {
        super(order_entity_1.Order, dataSource.createEntityManager());
        this.dataSource = dataSource;
    }
    async createOrder(dto) {
        const user = await this.manager.findOne(user_entity_1.User, {
            where: { id: dto.userId },
        });
        if (!user) {
            throw new common_1.NotFoundException('User not found');
        }
        const products = await this.manager.find(product_entity_1.Product, {
            where: { id: (0, typeorm_1.In)(dto.productIds) },
        });
        if (products.length === 0) {
            throw new common_1.NotFoundException('No products found');
        }
        const totalPrice = products.reduce((sum, p) => sum + Number(p.price), 0);
        const order = this.create({
            user,
            products,
            totalPrice,
            status: dto.status,
            orderNumber: `ORD-${Date.now()}`,
        });
        return this.save(order);
    }
    async findAllOrders() {
        return this.find();
    }
    async findOrdersWithFilters(filters) {
        const query = this.createQueryBuilder('order').leftJoinAndSelect('order.user', 'user');
        if (filters.search) {
            query.where('order.orderNumber ILIKE :search', {
                search: `%${filters.search}%`,
            });
        }
        if (filters.status) {
            query.andWhere('order.status = :status', { status: filters.status });
        }
        const total = await query.getCount();
        const skip = ((filters.page || 1) - 1) * (filters.limit || 10);
        query.skip(skip).take(filters.limit || 10);
        query.orderBy('order.createdAt', 'DESC');
        const orders = await query.getMany();
        return { orders, total };
    }
    async findOrderById(id) {
        const order = await this.findOne({ where: { id } });
        if (!order)
            throw new common_1.NotFoundException('Order not found');
        return order;
    }
    async updateStatus(id, status) {
        const order = await this.findOne({ where: { id } });
        if (!order)
            throw new common_1.NotFoundException('Order not found');
        order.status = status;
        if (status === order_status_enum_1.OrderStatus.CONFIRMED && !order.paidAt) {
            order.paidAt = new Date();
        }
        return this.save(order);
    }
};
exports.OrderRepository = OrderRepository;
exports.OrderRepository = OrderRepository = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeorm_1.DataSource])
], OrderRepository);
//# sourceMappingURL=order.repository.js.map