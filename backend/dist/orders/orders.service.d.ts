import { OrderRepository } from './order.repository';
import { CreateOrderDto } from './dto/create-order.dto';
import { ApiResponse } from 'src/common/response';
import { UpdateOrderStatusDto } from './dto/update-order-status.dto';
import { OrderFilterDto } from 'src/common/dto/pagination.dto';
import { PaginatedResponse } from 'src/common/PaginatedResponse';
export declare class OrdersService {
    private readonly orderRepo;
    constructor(orderRepo: OrderRepository);
    create(dto: CreateOrderDto): Promise<ApiResponse<any>>;
    findAll(): Promise<ApiResponse<any>>;
    findWithFilters(filters: OrderFilterDto): Promise<PaginatedResponse<any>>;
    findOne(id: number): Promise<ApiResponse<any>>;
    updateStatus(id: number, dto: UpdateOrderStatusDto): Promise<ApiResponse<any>>;
}
