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
exports.OrdersService = void 0;
const common_1 = require("@nestjs/common");
const order_repository_1 = require("./order.repository");
let OrdersService = class OrdersService {
    orderRepo;
    constructor(orderRepo) {
        this.orderRepo = orderRepo;
    }
    async create(dto) {
        const order = await this.orderRepo.createOrder(dto);
        return {
            success: true,
            message: 'Order created successfully',
            data: order,
        };
    }
    async findAll() {
        const orders = await this.orderRepo.findAllOrders();
        return {
            success: true,
            message: 'Orders fetched successfully',
            data: orders,
        };
    }
    async findWithFilters(filters) {
        const { orders, total } = await this.orderRepo.findOrdersWithFilters(filters);
        const page = filters.page || 1;
        const limit = filters.limit || 10;
        const totalPages = Math.ceil(total / limit);
        return {
            success: true,
            message: 'Orders fetched successfully',
            data: orders,
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
        const order = await this.orderRepo.findOrderById(id);
        return {
            success: true,
            message: 'Order fetched successfully',
            data: order,
        };
    }
    async updateStatus(id, dto) {
        const order = await this.orderRepo.updateStatus(id, dto.status);
        return {
            success: true,
            message: 'Order status updated successfully',
            data: order,
        };
    }
};
exports.OrdersService = OrdersService;
exports.OrdersService = OrdersService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [order_repository_1.OrderRepository])
], OrdersService);
//# sourceMappingURL=orders.service.js.map