import { UserRole } from '../dto/create-user.dto';
import { Product } from '../../products/entities/product.entity';
import { Order } from '../../orders/entities/order.entity';
export declare class User {
    id: number;
    name: string;
    email: string;
    password: string;
    role: UserRole;
    products: Product[];
    orders: Order[];
}
