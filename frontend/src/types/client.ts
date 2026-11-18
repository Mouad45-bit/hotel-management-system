export interface Client {
    id: number;
    firstName: string;
    lastName: string;
    email?: string;
    phone?: string;
    cin?: string;
    passportNumber?: string;
    nationality?: string;
    address?: string;
    birthDate?: string;
    active: boolean;
    createdAt?: string;
    updatedAt?: string;
}
