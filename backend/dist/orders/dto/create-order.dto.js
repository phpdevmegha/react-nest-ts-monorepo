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
exports.CreateOrderDto = void 0;
const class_validator_1 = require("class-validator");
const order_status_enum_1 = require("../enum/order-status.enum");
class CreateOrderDto {
    userId;
    productIds;
    status;
}
exports.CreateOrderDto = CreateOrderDto;
__decorate([
    (0, class_validator_1.IsNotEmpty)({ message: 'User ID is required' }),
    (0, class_validator_1.IsNumber)({}, { message: 'User ID must be a number' }),
    (0, class_validator_1.IsPositive)({ message: 'User ID must be a positive number' }),
    __metadata("design:type", Number)
], CreateOrderDto.prototype, "userId", void 0);
__decorate([
    (0, class_validator_1.IsArray)({ message: 'Product IDs must be an array' }),
    (0, class_validator_1.ArrayNotEmpty)({ message: 'At least one product is required' }),
    (0, class_validator_1.IsNumber)({}, { each: true, message: 'Each product ID must be a number' }),
    __metadata("design:type", Array)
], CreateOrderDto.prototype, "productIds", void 0);
__decorate([
    (0, class_validator_1.IsEnum)(order_status_enum_1.OrderStatus, {
        message: `Status must be one of: ${Object.values(order_status_enum_1.OrderStatus).join(', ')}`,
    }),
    (0, class_validator_1.IsNotEmpty)({ message: 'Status is required' }),
    __metadata("design:type", String)
], CreateOrderDto.prototype, "status", void 0);
//# sourceMappingURL=create-order.dto.js.map