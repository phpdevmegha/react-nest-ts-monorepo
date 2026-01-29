import { DataSource, Repository } from 'typeorm';
import { Order } from './entities/order.entity';
import { CreateOrderDto } from './dto/create-order.dto';
import { OrderStatus } from './enum/order-status.enum';
import { OrderFilterDto } from 'src/common/dto/pagination.dto';
export declare class OrderRepository extends Repository<Order> {
    private dataSource;
    constructor(dataSource: DataSource);
    createOrder(dto: CreateOrderDto): Promise<Order>;
    findAllOrders(): Promise<Order[]>;
    findOrdersWithFilters(filters: OrderFilterDto): Promise<{
        orders: Order[];
        total: number;
    }>;
    findOrderById(id: number): Promise<Order>;
    updateStatus(id: number, status: OrderStatus): Promise<Order>;
}
