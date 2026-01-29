import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserFilterDto } from 'src/common/dto/pagination.dto';
export declare class UsersController {
    private readonly usersService;
    constructor(usersService: UsersService);
    findAll(filters: UserFilterDto): Promise<import("../common/response").ApiResponse<import("./entities/user.entity").User[]>>;
    findOne(id: number): Promise<import("../common/response").ApiResponse<import("./entities/user.entity").User>>;
    create(createUserDto: CreateUserDto): Promise<import("../common/response").ApiResponse<import("./entities/user.entity").User>>;
    update(id: number, updateUserDto: UpdateUserDto): Promise<import("../common/response").ApiResponse<import("./entities/user.entity").User>>;
    delete(id: number): Promise<import("../common/response").ApiResponse<null>>;
}
