import { apiFetch } from '@/lib/api';
import { Room, RoomStats } from '@/types/room';

export interface RoomFilters {
    number?: string;
    type?: string;
    status?: string;
    floor?: number;
    capacity?: number;
}

export const RoomService = {
    getRooms: async (filters?: RoomFilters): Promise<Room[]> => {
        const params = new URLSearchParams();
        if (filters?.number) params.set('number', filters.number);
        if (filters?.type) params.set('type', filters.type);
        if (filters?.status) params.set('status', filters.status);
        if (filters?.floor !== undefined) params.set('floor', String(filters.floor));
        if (filters?.capacity !== undefined) params.set('capacity', String(filters.capacity));
        const qs = params.toString();
        return apiFetch<Room[]>(`/api/rooms${qs ? `?${qs}` : ''}`, { cache: 'no-store' });
    },

    getDisabledRooms: async (): Promise<Room[]> => {
        return apiFetch<Room[]>('/api/rooms/disabled', { cache: 'no-store' });
    },



    getRoomById: async (id: number): Promise<Room> => {
        return apiFetch<Room>(`/api/rooms/${id}`);
    },

    getStats: async (): Promise<RoomStats> => {
        return apiFetch<RoomStats>('/api/rooms/stats');
    },

    createRoom: async (data: Omit<Room, 'id'>): Promise<Room> => {
        return apiFetch<Room>('/api/rooms', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    },

    updateRoom: async (id: number, data: Partial<Room>): Promise<Room> => {
        return apiFetch<Room>(`/api/rooms/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    },

    updateStatus: async (id: number, status: string): Promise<Room> => {
        return apiFetch<Room>(`/api/rooms/${id}/status`, {
            method: 'PATCH',
            body: JSON.stringify({ status }),
        });
    },

    deleteRoom: async (id: number): Promise<void> => {
        return apiFetch<void>(`/api/rooms/${id}`, { method: 'DELETE' });
    },

    activateRoom: async (id: number): Promise<void> => {
        const baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";
        // L'API Java renvoie un 200 OK sans corps JSON, on utilise fetch directement
        const response = await fetch(`${baseUrl}/api/rooms/${id}/activate`, {
            method: 'PATCH'
        });
        if (!response.ok) throw new Error("Erreur lors de la réactivation");
    }
};
