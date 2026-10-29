import { CreateProductDto } from './create-product.dto';
import { PartialType } from '@nestjs/mapped-types';

/**
 * Partial update — every field from CreateProductDto (including its
 * validation decorators) becomes optional.
 */
export class UpdateProductDto extends PartialType(CreateProductDto) {}
