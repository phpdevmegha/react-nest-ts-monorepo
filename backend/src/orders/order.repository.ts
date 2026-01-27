import { Injectable, NotFoundException } from '@nestjs/common';
import { DataSource, Repository, In } from 'typeorm';
import { Order } from './entities/order.entity';
import { CreateOrderDto } from './dto/create-order.dto';
import { User } from 'src/users/entities/user.entity';
import { Product } from 'src/products/entities/product.entity';
import { OrderStatus } from './enum/order-status.enum';
import { OrderFilterDto } from 'src/common/dto/pagination.dto';

@Injectable()
export class OrderRepository extends Repository<Order> {
  constructor(private dataSource: DataSource) {
    super(Order, dataSource.createEntityManager());
  }

  async createOrder(dto: CreateOrderDto): Promise<Order> {
    const user = await this.manager.findOne(User, {
      where: { id: dto.userId },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const products = await this.manager.find(Product, {
      where: { id: In(dto.productIds) },
    });
    if (products.length === 0) {
      throw new NotFoundException('No products found');
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

  async findAllOrders(): Promise<Order[]> {
    return this.find();
  }

  async findOrdersWithFilters(filters: OrderFilterDto): Promise<{ orders: Order[]; total: number }> {
    const query = this.createQueryBuilder('order').leftJoinAndSelect('order.user', 'user');

    // Search by order number
    if (filters.search) {
      query.where('order.orderNumber ILIKE :search', {
        search: `%${filters.search}%`,
      });
    }

    // Filter by status
    if (filters.status) {
      query.andWhere('order.status = :status', { status: filters.status });
    }

    // Get total count
    const total = await query.getCount();

    // Pagination
    const skip = ((filters.page || 1) - 1) * (filters.limit || 10);
    query.skip(skip).take(filters.limit || 10);
    query.orderBy('order.createdAt', 'DESC');

    const orders = await query.getMany();
    return { orders, total };
  }

  async findOrderById(id: number): Promise<Order> {
    const order = await this.findOne({ where: { id } });
    if (!order) throw new NotFoundException('Order not found');
    return order;
  }
  async updateStatus(id: number, status: OrderStatus): Promise<Order> {
    const order = await this.findOne({ where: { id } });
    if (!order) throw new NotFoundException('Order not found');
    order.status = status;
    if (status === OrderStatus.CONFIRMED && !order.paidAt) {
      order.paidAt = new Date();
    }

    return this.save(order);
  }
}
