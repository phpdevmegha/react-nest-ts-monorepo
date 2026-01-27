import { Injectable } from '@nestjs/common';
import { DataSource, Repository, ILike } from 'typeorm';
import { User } from './entities/user.entity';
import { UserRole } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserFilterDto } from 'src/common/dto/pagination.dto';

@Injectable()
export class UserRepository extends Repository<User> {
  constructor(private dataSource: DataSource) {
    super(User, dataSource.createEntityManager());
  }

  findAllUsers(role?: UserRole): Promise<User[]> {
    if (role) return this.find({ where: { role } });
    return this.find();
  }

  async findUsersWithFilters(filters: UserFilterDto): Promise<{ users: User[]; total: number }> {
    const query = this.createQueryBuilder('user');

    // Search by name or email
    if (filters.search) {
      query.where(
        '(user.name ILIKE :search OR user.email ILIKE :search)',
        {
          search: `%${filters.search}%`,
        },
      );
    }

    // Filter by role
    if (filters.role) {
      query.andWhere('user.role = :role', { role: filters.role });
    }

    // Get total count
    const total = await query.getCount();

    // Pagination
    const skip = ((filters.page || 1) - 1) * (filters.limit || 10);
    query.skip(skip).take(filters.limit || 10);

    const users = await query.getMany();
    return { users, total };
  }

  findUserById(id: number): Promise<User | null> {
    return this.findOne({ where: { id } });
  }

  findByEmail(email: string): Promise<User | null> {
    return this.findOne({ where: { email } });
  }

  createUser(data: Partial<User>): Promise<User> {
    const user = this.create(data);
    return this.save(user);
  }

  async updateUser(id: number, data: UpdateUserDto): Promise<User | null> {
    await this.update(id, data);
    return this.findOne({ where: { id } });
  }

  async deleteUser(id: number): Promise<void> {
    await this.delete(id);
  }
}
