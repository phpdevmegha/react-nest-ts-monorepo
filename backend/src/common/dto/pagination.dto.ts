import { IsOptional, IsNumber, Min, Max, IsString } from 'class-validator';
import { Type } from 'class-transformer';

export class PaginationDto {
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(100)
  limit?: number = 10;
}

export class SearchDto extends PaginationDto {
  @IsOptional()
  @IsString()
  search?: string;
}

export class ProductFilterDto extends SearchDto {
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  minPrice?: number;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  maxPrice?: number;

  @IsOptional()
  @IsString()
  sortBy?: 'price' | 'title' | 'newest' = 'newest';

  @IsOptional()
  @IsString()
  order?: 'ASC' | 'DESC' = 'DESC';
}

export class UserFilterDto extends SearchDto {
  @IsOptional()
  @IsString()
  role?: 'ADMIN' | 'MANAGER' | 'VENDOR';
}

export class OrderFilterDto extends SearchDto {
  @IsOptional()
  @IsString()
  status?: 'PENDING' | 'PROCESSING' | 'SHIPPED' | 'DELIVERED';
}
