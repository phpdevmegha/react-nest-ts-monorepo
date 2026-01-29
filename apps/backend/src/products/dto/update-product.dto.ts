import { CreateProductDto } from './create-product.dto';
import { PartialType } from '@nestjs/mapped-types';
import { IsOptional } from 'class-validator';

export class UpdateProductDto extends PartialType(CreateProductDto) {
  // All fields are optional for partial updates
  @IsOptional()
  title?: string;

  @IsOptional()
  price?: number;
}
