import { IsEnum, IsNotEmpty } from 'class-validator';
import { OrderStatus } from '../enum/order-status.enum';

export class UpdateOrderStatusDto {
  @IsEnum(OrderStatus, {
    message: `Status must be one of: ${Object.values(OrderStatus).join(', ')}`,
  })
  @IsNotEmpty({ message: 'Status is required' })
  status: OrderStatus;
}
