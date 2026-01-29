import {
  IsEnum,
  IsNumber,
  ArrayNotEmpty,
  IsArray,
  IsNotEmpty,
  IsPositive,
} from 'class-validator';
import { OrderStatus } from '../enum/order-status.enum';

export class CreateOrderDto {
  @IsNotEmpty({ message: 'User ID is required' })
  @IsNumber({}, { message: 'User ID must be a number' })
  @IsPositive({ message: 'User ID must be a positive number' })
  userId: number;

  @IsArray({ message: 'Product IDs must be an array' })
  @ArrayNotEmpty({ message: 'At least one product is required' })
  @IsNumber({}, { each: true, message: 'Each product ID must be a number' })
  productIds: number[];

  @IsEnum(OrderStatus, {
    message: `Status must be one of: ${Object.values(OrderStatus).join(', ')}`,
  })
  @IsNotEmpty({ message: 'Status is required' })
  status: OrderStatus;
}
