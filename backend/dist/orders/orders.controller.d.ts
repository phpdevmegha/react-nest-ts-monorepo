import { OrdersService } from './orders.service';
import { CreateOrderDto } from './dto/create-order.dto';
import { UpdateOrderStatusDto } from './dto/update-order-status.dto';
import { OrderFilterDto } from 'src/common/dto/pagination.dto';
export declare class OrdersController {
    private readonly ordersService;
    constructor(ordersService: OrdersService);
    create(dto: CreateOrderDto): Promise<import("../common/response").ApiResponse<any>>;
    findAll(filters: OrderFilterDto): Promise<import("../common/response").ApiResponse<any>>;
    findOne(id: number): Promise<import("../common/response").ApiResponse<any>>;
    updateStatus(id: number, dto: UpdateOrderStatusDto): Promise<import("../common/response").ApiResponse<any>>;
}
