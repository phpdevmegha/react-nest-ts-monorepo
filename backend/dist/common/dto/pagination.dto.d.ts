export declare class PaginationDto {
    page?: number;
    limit?: number;
}
export declare class SearchDto extends PaginationDto {
    search?: string;
}
export declare class ProductFilterDto extends SearchDto {
    minPrice?: number;
    maxPrice?: number;
    sortBy?: 'price' | 'title' | 'newest';
    order?: 'ASC' | 'DESC';
}
export declare class UserFilterDto extends SearchDto {
    role?: 'ADMIN' | 'MANAGER' | 'VENDOR';
}
export declare class OrderFilterDto extends SearchDto {
    status?: 'PENDING' | 'PROCESSING' | 'SHIPPED' | 'DELIVERED';
}
