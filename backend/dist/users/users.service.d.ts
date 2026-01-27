import { UserRepository } from './user.repository';
import { CreateUserDto, UserRole } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import { ApiResponse } from 'src/common/response';
import { UserFilterDto } from 'src/common/dto/pagination.dto';
import { PaginatedResponse } from 'src/common/PaginatedResponse';
export declare class UsersService {
    private readonly repo;
    constructor(repo: UserRepository);
    findAll(role?: UserRole): Promise<ApiResponse<User[]>>;
    findWithFilters(filters: UserFilterDto): Promise<PaginatedResponse<User>>;
    findOne(id: number): Promise<ApiResponse<User>>;
    findByEmail(email: string): Promise<User | null>;
    create(dto: CreateUserDto): Promise<ApiResponse<User>>;
    update(id: number, dto: UpdateUserDto): Promise<ApiResponse<User>>;
    delete(id: number): Promise<ApiResponse<null>>;
}
