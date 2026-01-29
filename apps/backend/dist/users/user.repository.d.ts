import { DataSource, Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { UserRole } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserFilterDto } from 'src/common/dto/pagination.dto';
export declare class UserRepository extends Repository<User> {
    private dataSource;
    constructor(dataSource: DataSource);
    findAllUsers(role?: UserRole): Promise<User[]>;
    findUsersWithFilters(filters: UserFilterDto): Promise<{
        users: User[];
        total: number;
    }>;
    findUserById(id: number): Promise<User | null>;
    findByEmail(email: string): Promise<User | null>;
    createUser(data: Partial<User>): Promise<User>;
    updateUser(id: number, data: UpdateUserDto): Promise<User | null>;
    deleteUser(id: number): Promise<void>;
}
