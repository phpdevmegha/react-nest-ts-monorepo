import { Injectable } from '@nestjs/common';
import { OrderRepository } from './order.repository';
import { CreateOrderDto } from './dto/create-order.dto';
import { ApiResponse } from 'src/common/response';
import { UpdateOrderStatusDto } from './dto/update-order-status.dto';
import { OrderFilterDto } from 'src/common/dto/pagination.dto';
import { PaginatedResponse } from 'src/common/PaginatedResponse';

@Injectable()
export class OrdersService {
  constructor(private readonly orderRepo: OrderRepository) {}

  async create(dto: CreateOrderDto): Promise<ApiResponse<any>> {
    const order = await this.orderRepo.createOrder(dto);
    return {
      success: true,
      message: 'Order created successfully',
      data: order,
    };
  }

  async findAll(): Promise<ApiResponse<any>> {
    const orders = await this.orderRepo.findAllOrders();
    return {
      success: true,
      message: 'Orders fetched successfully',
      data: orders,
    };
  }

  async findWithFilters(
    filters: OrderFilterDto,
  ): Promise<PaginatedResponse<any>> {
    const { orders, total } =
      await this.orderRepo.findOrdersWithFilters(filters);

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

  async findOne(id: number): Promise<ApiResponse<any>> {
    const order = await this.orderRepo.findOrderById(id);
    return {
      success: true,
      message: 'Order fetched successfully',
      data: order,
    };
  }

  async updateStatus(
    id: number,
    dto: UpdateOrderStatusDto,
  ): Promise<ApiResponse<any>> {
    const order = await this.orderRepo.updateStatus(id, dto.status);
    return {
      success: true,
      message: 'Order status updated successfully',
      data: order,
    };
  }
}
