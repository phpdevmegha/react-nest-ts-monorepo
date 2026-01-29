import { Injectable, NotFoundException } from '@nestjs/common';
import { UserRepository } from './user.repository';
import { CreateUserDto, UserRole } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import { ApiResponse } from 'src/common/response';
import { UserFilterDto } from 'src/common/dto/pagination.dto';
import { PaginatedResponse } from 'src/common/PaginatedResponse';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(private readonly repo: UserRepository) {}

  async findAll(role?: UserRole): Promise<ApiResponse<User[]>> {
    const users = await this.repo.findAllUsers(role);
    if (users.length === 0) {
      throw new NotFoundException(
        role ? 'User Role not found' : 'Users not found',
      );
    }

    return {
      success: true,
      message: 'Users fetched successfully',
      data: users,
    };
  }

  async findWithFilters(
    filters: UserFilterDto,
  ): Promise<PaginatedResponse<User>> {
    const { users, total } = await this.repo.findUsersWithFilters(filters);

    const page = filters.page || 1;
    const limit = filters.limit || 10;
    const totalPages = Math.ceil(total / limit);

    return {
      success: true,
      message: 'Users fetched successfully',
      data: users,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasMore: page < totalPages,
      },
    };
  }

  async findOne(id: number): Promise<ApiResponse<User>> {
    const user = await this.repo.findUserById(id);
    if (!user) throw new NotFoundException('User not found');

    return {
      success: true,
      message: 'User fetched successfully',
      data: user,
    };
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.repo.findByEmail(email);
  }

  async create(dto: CreateUserDto): Promise<ApiResponse<User>> {
    const hashed = await bcrypt.hash(dto.password, 8);
    const user = await this.repo.createUser({ ...dto, password: hashed });
    return {
      success: true,
      message: 'User created successfully',
      data: user,
    };
  }

  async update(id: number, dto: UpdateUserDto): Promise<ApiResponse<User>> {
    const existing = await this.repo.findUserById(id);
    if (!existing) throw new NotFoundException('User not found');

    const updated = await this.repo.updateUser(id, dto);
    if (!updated) throw new NotFoundException('User not found after update');
    return {
      success: true,
      message: 'User updated successfully',
      data: updated,
    };
  }

  async delete(id: number): Promise<ApiResponse<null>> {
    const existing = await this.repo.findUserById(id);
    if (!existing) throw new NotFoundException('User not found');

    await this.repo.deleteUser(id);

    return {
      success: true,
      message: 'User deleted successfully',
      data: null,
    };
  }
}
