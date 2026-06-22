import { apiFetch } from '@/lib/api';
import { Reservation } from '@/types/reservation';

export interface ReservationFilters {
    status?: string;
    roomId?: number;
    clientId?: number;
}

export const ReservationService = {
    getReservations: async (filters?: ReservationFilters): Promise<Reservation[]> => {
        const params = new URLSearchParams();
        if (filters?.status) params.set('status', filters.status);
        if (filters?.roomId) params.set('roomId', String(filters.roomId));
        if (filters?.clientId) params.set('clientId', String(filters.clientId));
        const qs = params.toString();
        return apiFetch<Reservation[]>(`/api/reservations${qs ? `?${qs}` : ''}`, { cache: 'no-store' });
    },

    getReservationById: async (id: number): Promise<Reservation> => {
        return apiFetch<Reservation>(`/api/reservations/${id}`);
    },

    createReservation: async (data: { roomId: number; clientId: number; checkInDate: string; checkOutDate: string; notes?: string }): Promise<Reservation> => {
        return apiFetch<Reservation>('/api/reservations', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    },

    updateReservation: async (id: number, data: { checkInDate?: string; checkOutDate?: string; notes?: string }): Promise<Reservation> => {
        return apiFetch<Reservation>(`/api/reservations/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    },

    deleteReservation: async (id: number): Promise<void> => {
        return apiFetch<void>(`/api/reservations/${id}`, { method: 'DELETE' });
    },

    confirmReservation: async (id: number): Promise<Reservation> => {
        return apiFetch<Reservation>(`/api/reservations/${id}/confirm`, { method: 'PATCH' });
    },

    checkIn: async (id: number): Promise<Reservation> => {
        return apiFetch<Reservation>(`/api/reservations/${id}/check-in`, { method: 'PATCH' });
    },

    checkOut: async (id: number): Promise<Reservation> => {
        return apiFetch<Reservation>(`/api/reservations/${id}/check-out`, { method: 'PATCH' });
    },

    cancelReservation: async (id: number): Promise<Reservation> => {
        return apiFetch<Reservation>(`/api/reservations/${id}/cancel`, { method: 'PATCH' });
    },

    noShow: async (id: number): Promise<Reservation> => {
        return apiFetch<Reservation>(`/api/reservations/${id}/no-show`, { method: 'PATCH' });
    },

    getReservationsByClient: async (clientId: number): Promise<Reservation[]> => {
        return apiFetch<Reservation[]>(`/api/reservations/client/${clientId}`, { cache: 'no-store' });
    },

    getReservationsByRoom: async (roomId: number): Promise<Reservation[]> => {
        return apiFetch<Reservation[]>(`/api/reservations/room/${roomId}`, { cache: 'no-store' });
    },

    getTodayCheckIns: async (): Promise<Reservation[]> => {
        return apiFetch<Reservation[]>('/api/reservations/today/check-ins', { cache: 'no-store' });
    },

    getTodayCheckOuts: async (): Promise<Reservation[]> => {
        return apiFetch<Reservation[]>('/api/reservations/today/check-outs', { cache: 'no-store' });
    },
};
