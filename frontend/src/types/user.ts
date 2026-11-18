export type UserRole = 'ADMIN' | 'MANAGER' | 'RECEPTIONIST' | 'HOUSEKEEPING_AGENT' | 'HR';

export interface User {
    id: number;
    username: string;
    email: string | null;
    firstName: string;
    lastName: string;
    role: UserRole;
    active: boolean;
    createdAt: string;
    updatedAt: string;
}
