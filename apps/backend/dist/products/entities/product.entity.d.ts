import { User } from '../../users/entities/user.entity';
export declare class Product {
    id: number;
    title: string;
    price: number;
    userId: number;
    user: User;
}
