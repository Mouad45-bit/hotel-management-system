import { apiFetch } from '@/lib/api';
import { User } from '@/types/user';

export interface LoginPayload {
    username: string;
    password: string;
}

export interface LoginResult {
    accessToken: string;
    refreshToken: string;
    tokenType: string;
}

export interface CreateUserPayload {
    username: string;
    email?: string;
    password: string;
    firstName: string;
    lastName: string;
    role: string;
}

export interface UpdateUserPayload {
    email?: string;
    firstName?: string;
    lastName?: string;
    role?: string;
}

export interface ChangePasswordPayload {
    oldPassword: string;
    newPassword: string;
}

export const AuthService = {
    login: (data: LoginPayload): Promise<LoginResult> =>
        apiFetch('/api/auth/login', { method: 'POST', body: JSON.stringify(data) }),

    refresh: (refreshToken: string): Promise<LoginResult> =>
        apiFetch('/api/auth/refresh', { method: 'POST', body: JSON.stringify({ refreshToken }) }),

    getMe: (): Promise<User> =>
        apiFetch('/api/auth/me'),

    createUser: (data: CreateUserPayload): Promise<User> =>
        apiFetch('/api/auth/users', { method: 'POST', body: JSON.stringify(data) }),

    getUsers: (): Promise<User[]> =>
        apiFetch('/api/auth/users', { cache: 'no-store' }),

    getUserById: (id: number): Promise<User> =>
        apiFetch(`/api/auth/users/${id}`),

    updateUser: (id: number, data: UpdateUserPayload): Promise<User> =>
        apiFetch(`/api/auth/users/${id}`, { method: 'PUT', body: JSON.stringify(data) }),

    activateUser: (id: number): Promise<User> =>
        apiFetch(`/api/auth/users/${id}/activate`, { method: 'PATCH' }),

    deactivateUser: (id: number): Promise<User> =>
        apiFetch(`/api/auth/users/${id}/deactivate`, { method: 'PATCH' }),

    changePassword: (id: number, data: ChangePasswordPayload): Promise<void> =>
        apiFetch(`/api/auth/users/${id}/change-password`, { method: 'PATCH', body: JSON.stringify(data) }),
};
