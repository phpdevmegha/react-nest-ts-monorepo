import { OrderStatus } from '../enum/order-status.enum';
export declare class CreateOrderDto {
    userId: number;
    productIds: number[];
    status: OrderStatus;
}
