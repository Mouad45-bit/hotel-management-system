import { apiFetch } from "@/lib/api";
import type {
    AssignHousekeepingTaskRequest,
    CancelHousekeepingTaskRequest,
    CreateHousekeepingTaskRequest,
    HousekeepingAgentOption,
    HousekeepingRoomOption,
    HousekeepingStats,
    HousekeepingTask,
    HousekeepingTaskSearchParams,
    PageResponse,
    RoomCleaningHistoryItem,
    UpdateHousekeepingTaskRequest,
} from "@/types/housekeeping";
import type { Room } from "@/types/room";

function buildQueryString(params: HousekeepingTaskSearchParams): string {
    const searchParams = new URLSearchParams();

    Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== "") {
            searchParams.set(key, String(value));
        }
    });

    const queryString = searchParams.toString();

    return queryString ? `?${queryString}` : "";
}

export async function getHousekeepingTasks(
    params: HousekeepingTaskSearchParams = {}
): Promise<PageResponse<HousekeepingTask>> {
    const queryString = buildQueryString(params);

    return apiFetch<PageResponse<HousekeepingTask>>(
        `/api/housekeeping-tasks${queryString}`
    );
}

export async function getHousekeepingTaskById(
    id: number
): Promise<HousekeepingTask> {
    return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}`);
}

export async function createHousekeepingTask(
    request: CreateHousekeepingTaskRequest
): Promise<HousekeepingTask> {
    return apiFetch<HousekeepingTask>("/api/housekeeping-tasks", {
        method: "POST",
        body: JSON.stringify(request),
    });
}

export async function updateHousekeepingTask(
    id: number,
    request: UpdateHousekeepingTaskRequest
): Promise<HousekeepingTask> {
    return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}`, {
        method: "PUT",
        body: JSON.stringify(request),
    });
}

export async function assignHousekeepingTask(
    id: number,
    request: AssignHousekeepingTaskRequest
): Promise<HousekeepingTask> {
    return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}/assign`, {
        method: "PATCH",
        body: JSON.stringify(request),
    });
}

export async function startHousekeepingTask(id: number): Promise<HousekeepingTask> {
    return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}/start`, {
        method: "PATCH",
    });
}

export async function completeHousekeepingTask(
    id: number
): Promise<HousekeepingTask> {
    return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}/complete`, {
        method: "PATCH",
    });
}

export async function cancelHousekeepingTask(
    id: number,
    request: CancelHousekeepingTaskRequest
): Promise<HousekeepingTask> {
    return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}/cancel`, {
        method: "PATCH",
        body: JSON.stringify(request),
    });
}

export async function getTodayHousekeepingTasks(): Promise<HousekeepingTask[]> {
    return apiFetch<HousekeepingTask[]>("/api/housekeeping-tasks/today");
}

export async function getHousekeepingTasksByRoomId(
    roomId: number
): Promise<RoomCleaningHistoryItem[]> {
    return apiFetch<RoomCleaningHistoryItem[]>(
        `/api/housekeeping-tasks/room/${roomId}`
    );
}

export async function getHousekeepingTasksByAgentId(
    agentId: number
): Promise<HousekeepingTask[]> {
    return apiFetch<HousekeepingTask[]>(
        `/api/housekeeping-tasks/agent/${agentId}`
    );
}

export async function getHousekeepingStats(): Promise<HousekeepingStats> {
    return apiFetch<HousekeepingStats>("/api/housekeeping-tasks/stats");
}

export async function getHousekeepingAgents(): Promise<HousekeepingAgentOption[]> {
    const response = await apiFetch<PageResponse<HousekeepingAgentOption>>(
        "/api/employees?department=HOUSEKEEPING&active=true&size=100"
    );

    return response.content;
}

export async function getHousekeepingRooms(): Promise<HousekeepingRoomOption[]> {
    const rooms = await apiFetch<Room[]>("/api/rooms?active=true");

    return rooms.map((room) => ({
        id: room.id,
        roomNumber: room.number,
        floor: room.floor,
        status: room.status,
    }));
}
