import { User } from '../../users/entities/user.entity';
import { Product } from '../../products/entities/product.entity';
import { OrderStatus } from '../enum/order-status.enum';
export declare class Order {
    id: number;
    orderNumber: string;
    user: User;
    products: Product[];
    totalPrice: number;
    status: OrderStatus;
    paidAt: Date;
    createdAt: Date;
    updatedAt: Date;
}
