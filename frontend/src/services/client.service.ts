import { apiFetch } from '@/lib/api';
import { Client } from '@/types/client';

export interface ClientFilters {
    search?: string;
}

export const ClientService = {
    getClients: async (filters?: ClientFilters): Promise<Client[]> => {
        const params = new URLSearchParams();
        if (filters?.search) params.set('search', filters.search);
        const qs = params.toString();
        return apiFetch<Client[]>(`/api/clients${qs ? `?${qs}` : ''}`, { cache: 'no-store' });
    },

    getInactiveClients: async (): Promise<Client[]> => {
        return apiFetch<Client[]>('/api/clients?active=false', { cache: 'no-store' });
    },

    getClientById: async (id: number): Promise<Client> => {
        return apiFetch<Client>(`/api/clients/${id}`);
    },

    searchClients: async (q: string): Promise<Client[]> => {
        return apiFetch<Client[]>(`/api/clients/search?q=${encodeURIComponent(q)}`, { cache: 'no-store' });
    },

    createClient: async (data: Omit<Client, 'id' | 'active' | 'createdAt' | 'updatedAt'>): Promise<Client> => {
        return apiFetch<Client>('/api/clients', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    },

    updateClient: async (id: number, data: Partial<Client>): Promise<Client> => {
        return apiFetch<Client>(`/api/clients/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    },

    deleteClient: async (id: number): Promise<void> => {
        return apiFetch<void>(`/api/clients/${id}`, { method: 'DELETE' });
    },

    activateClient: async (id: number): Promise<void> => {
        const baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8080';
        const response = await fetch(`${baseUrl}/api/clients/${id}/activate`, { method: 'PATCH' });
        if (!response.ok) throw new Error('Erreur lors de la réactivation');
    },

    deactivateClient: async (id: number): Promise<void> => {
        const baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8080';
        const response = await fetch(`${baseUrl}/api/clients/${id}/deactivate`, { method: 'PATCH' });
        if (!response.ok) throw new Error('Erreur lors de la désactivation');
    },
};
