"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UsersService = void 0;
const common_1 = require("@nestjs/common");
const user_repository_1 = require("./user.repository");
const bcrypt = __importStar(require("bcrypt"));
let UsersService = class UsersService {
    repo;
    constructor(repo) {
        this.repo = repo;
    }
    async findAll(role) {
        const users = await this.repo.findAllUsers(role);
        if (users.length === 0) {
            throw new common_1.NotFoundException(role ? 'User Role not found' : 'Users not found');
        }
        return {
            success: true,
            message: 'Users fetched successfully',
            data: users,
        };
    }
    async findWithFilters(filters) {
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
    async findOne(id) {
        const user = await this.repo.findUserById(id);
        if (!user)
            throw new common_1.NotFoundException('User not found');
        return {
            success: true,
            message: 'User fetched successfully',
            data: user,
        };
    }
    async findByEmail(email) {
        return this.repo.findByEmail(email);
    }
    async create(dto) {
        const hashed = await bcrypt.hash(dto.password, 8);
        const user = await this.repo.createUser({ ...dto, password: hashed });
        return {
            success: true,
            message: 'User created successfully',
            data: user,
        };
    }
    async update(id, dto) {
        const existing = await this.repo.findUserById(id);
        if (!existing)
            throw new common_1.NotFoundException('User not found');
        const updated = await this.repo.updateUser(id, dto);
        if (!updated)
            throw new common_1.NotFoundException('User not found after update');
        return {
            success: true,
            message: 'User updated successfully',
            data: updated,
        };
    }
    async delete(id) {
        const existing = await this.repo.findUserById(id);
        if (!existing)
            throw new common_1.NotFoundException('User not found');
        await this.repo.deleteUser(id);
        return {
            success: true,
            message: 'User deleted successfully',
            data: null,
        };
    }
};
exports.UsersService = UsersService;
exports.UsersService = UsersService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [user_repository_1.UserRepository])
], UsersService);
//# sourceMappingURL=users.service.js.map