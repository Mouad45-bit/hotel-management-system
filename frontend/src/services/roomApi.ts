import { apiFetch } from "@/lib/api";
import {
    CreateRoomRequest,
    Room,
    RoomSearchParams,
    RoomStats,
    UpdateRoomRequest,
    UpdateRoomStatusRequest,
} from "@/types/room";

function buildRoomQuery(params?: RoomSearchParams): string {
    if (!params) {
        return "";
    }

    const searchParams = new URLSearchParams();

    if (params.number) searchParams.set("number", params.number);
    if (params.type) searchParams.set("type", params.type);
    if (params.status) searchParams.set("status", params.status);
    if (params.floor !== undefined) searchParams.set("floor", String(params.floor));
    if (params.capacity !== undefined) {
        searchParams.set("capacity", String(params.capacity));
    }

    const query = searchParams.toString();

    return query ? `?${query}` : "";
}

export async function getRooms(params?: RoomSearchParams): Promise<Room[]> {
    return apiFetch<Room[]>(`/api/rooms${buildRoomQuery(params)}`);
}

export async function getRoomById(id: number): Promise<Room> {
    return apiFetch<Room>(`/api/rooms/${id}`);
}

export async function createRoom(payload: CreateRoomRequest): Promise<Room> {
    return apiFetch<Room>("/api/rooms", {
        method: "POST",
        body: JSON.stringify(payload),
    });
}

export async function updateRoom(
    id: number,
    payload: UpdateRoomRequest
): Promise<Room> {
    return apiFetch<Room>(`/api/rooms/${id}`, {
        method: "PUT",
        body: JSON.stringify(payload),
    });
}

export async function updateRoomStatus(
    id: number,
    payload: UpdateRoomStatusRequest
): Promise<Room> {
    return apiFetch<Room>(`/api/rooms/${id}/status`, {
        method: "PATCH",
        body: JSON.stringify(payload),
    });
}

export async function deleteRoom(id: number): Promise<void> {
    return apiFetch<void>(`/api/rooms/${id}`, {
        method: "DELETE",
    });
}

export async function getRoomStats(): Promise<RoomStats> {
    return apiFetch<RoomStats>("/api/rooms/stats");
}
