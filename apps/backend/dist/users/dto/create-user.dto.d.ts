export declare enum UserRole {
    ADMIN = "ADMIN",
    MANAGER = "MANAGER",
    VENDOR = "VENDOR"
}
export declare class CreateUserDto {
    name: string;
    email: string;
    password: string;
    role: UserRole;
}
