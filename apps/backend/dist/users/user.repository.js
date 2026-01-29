"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserRepository = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("typeorm");
const user_entity_1 = require("./entities/user.entity");
let UserRepository = class UserRepository extends typeorm_1.Repository {
    dataSource;
    constructor(dataSource) {
        super(user_entity_1.User, dataSource.createEntityManager());
        this.dataSource = dataSource;
    }
    findAllUsers(role) {
        if (role)
            return this.find({ where: { role } });
        return this.find();
    }
    async findUsersWithFilters(filters) {
        const query = this.createQueryBuilder('user');
        if (filters.search) {
            query.where('(user.name ILIKE :search OR user.email ILIKE :search)', {
                search: `%${filters.search}%`,
            });
        }
        if (filters.role) {
            query.andWhere('user.role = :role', { role: filters.role });
        }
        const total = await query.getCount();
        const skip = ((filters.page || 1) - 1) * (filters.limit || 10);
        query.skip(skip).take(filters.limit || 10);
        const users = await query.getMany();
        return { users, total };
    }
    findUserById(id) {
        return this.findOne({ where: { id } });
    }
    findByEmail(email) {
        return this.findOne({ where: { email } });
    }
    createUser(data) {
        const user = this.create(data);
        return this.save(user);
    }
    async updateUser(id, data) {
        await this.update(id, data);
        return this.findOne({ where: { id } });
    }
    async deleteUser(id) {
        await this.delete(id);
    }
};
exports.UserRepository = UserRepository;
exports.UserRepository = UserRepository = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeorm_1.DataSource])
], UserRepository);
//# sourceMappingURL=user.repository.js.map