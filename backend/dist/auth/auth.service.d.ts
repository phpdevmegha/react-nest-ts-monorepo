import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
export declare class AuthService {
    private readonly jwt;
    private readonly usersService;
    constructor(jwt: JwtService, usersService: UsersService);
    login(email: string, password: string): Promise<{
        message: string;
        token: string;
    }>;
}
