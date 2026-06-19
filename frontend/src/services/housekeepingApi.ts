import { apiFetch } from "@/lib/api";
import {
    mockHousekeepingAgents,
    mockHousekeepingRooms,
    mockHousekeepingTasks,
} from "@/mocks/housekeeping";
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

const USE_MOCK_API = process.env.NEXT_PUBLIC_USE_HOUSEKEEPING_MOCKS !== "false";

const MOCK_DELAY_MS = 150;

let housekeepingTaskStore: HousekeepingTask[] = mockHousekeepingTasks.map(clone);
let housekeepingRoomStore: HousekeepingRoomOption[] =
    mockHousekeepingRooms.map(clone);

function clone<T>(value: T): T {
    return JSON.parse(JSON.stringify(value)) as T;
}

function mockResponse<T>(value: T): Promise<T> {
    return new Promise((resolve) => {
        setTimeout(() => resolve(clone(value)), MOCK_DELAY_MS);
    });
}

function nowIsoDateTime(): string {
    return new Date().toISOString().slice(0, 19);
}

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

function todayIsoDate(): string {
    return new Date().toISOString().slice(0, 10);
}

function getTaskOrThrow(id: number): HousekeepingTask {
    const task = housekeepingTaskStore.find((item) => item.id === id);

    if (!task) {
        throw new Error(`Tâche housekeeping introuvable avec l'identifiant ${id}.`);
    }

    return task;
}

function getRoomOrThrow(roomId: number): HousekeepingRoomOption {
    const room = housekeepingRoomStore.find((item) => item.id === roomId);

    if (!room) {
        throw new Error(`Chambre introuvable avec l'identifiant ${roomId}.`);
    }

    return room;
}

function getAgentOrThrow(agentId: number): HousekeepingAgentOption {
    const agent = mockHousekeepingAgents.find(
        (item) => item.id === agentId && item.active
    );

    if (!agent) {
        throw new Error(`Agent housekeeping introuvable avec l'identifiant ${agentId}.`);
    }

    return agent;
}

function updateTask(
    id: number,
    updater: (task: HousekeepingTask) => HousekeepingTask
): HousekeepingTask {
    const currentTask = getTaskOrThrow(id);
    const updatedTask = {
        ...updater(currentTask),
        updatedAt: nowIsoDateTime(),
    };

    housekeepingTaskStore = housekeepingTaskStore.map((task) =>
        task.id === id ? updatedTask : task
    );

    return updatedTask;
}

function updateRoomStatus(
    roomId: number,
    status: HousekeepingRoomOption["status"]
) {
    housekeepingRoomStore = housekeepingRoomStore.map((room) =>
        room.id === roomId ? { ...room, status } : room
    );
}

function getNextTaskId(): number {
    return Math.max(0, ...housekeepingTaskStore.map((task) => task.id)) + 1;
}

function filterTasks(params: HousekeepingTaskSearchParams): HousekeepingTask[] {
    return housekeepingTaskStore.filter((task) => {
        const matchesStatus = !params.status || task.status === params.status;
        const matchesType = !params.type || task.type === params.type;
        const matchesPriority =
            !params.priority || task.priority === params.priority;
        const matchesRoom =
            params.roomId === undefined || task.roomId === params.roomId;
        const matchesAgent =
            params.agentId === undefined ||
            task.assignedAgentId === params.agentId;
        const matchesScheduledDate =
            !params.scheduledDate || task.scheduledDate === params.scheduledDate;

        return (
            matchesStatus &&
            matchesType &&
            matchesPriority &&
            matchesRoom &&
            matchesAgent &&
            matchesScheduledDate
        );
    });
}

function sortTasks(tasks: HousekeepingTask[], sort?: string): HousekeepingTask[] {
    const [field = "scheduledDate", direction = "asc"] = (
        sort || "scheduledDate,asc"
    ).split(",");

    const sortedTasks = [...tasks].sort((first, second) => {
        const firstValue = first[field as keyof HousekeepingTask];
        const secondValue = second[field as keyof HousekeepingTask];

        if (
            typeof firstValue === "number" &&
            typeof secondValue === "number"
        ) {
            return firstValue - secondValue;
        }

        return String(firstValue ?? "").localeCompare(String(secondValue ?? ""));
    });

    return direction === "desc" ? sortedTasks.reverse() : sortedTasks;
}

function createPageResponse<T>(
    content: T[],
    page: number,
    size: number
): PageResponse<T> {
    const startIndex = page * size;
    const paginatedContent = content.slice(startIndex, startIndex + size);

    return {
        content: paginatedContent,
        page,
        size,
        totalElements: content.length,
        totalPages: Math.ceil(content.length / size),
        last: startIndex + size >= content.length,
    };
}

function calculateStats(tasks: HousekeepingTask[]): HousekeepingStats {
    return {
        total: tasks.length,
        todo: tasks.filter((task) => task.status === "TODO").length,
        inProgress: tasks.filter((task) => task.status === "IN_PROGRESS").length,
        done: tasks.filter((task) => task.status === "DONE").length,
        cancelled: tasks.filter((task) => task.status === "CANCELLED").length,
        urgent: tasks.filter((task) => task.priority === "URGENT").length,
        unassigned: tasks.filter((task) => !task.assignedAgentId).length,
    };
}

function toHistoryItem(task: HousekeepingTask): RoomCleaningHistoryItem {
    return {
        ...task,
        durationMinutes:
            task.startedAt && task.completedAt
                ? Math.round(
                      (new Date(task.completedAt).getTime() -
                          new Date(task.startedAt).getTime()) /
                          60000
                  )
                : null,
    };
}

export async function getHousekeepingTasks(
    params: HousekeepingTaskSearchParams = {}
): Promise<PageResponse<HousekeepingTask>> {
    if (!USE_MOCK_API) {
        const queryString = buildQueryString(params);

        return apiFetch<PageResponse<HousekeepingTask>>(
            `/api/housekeeping-tasks${queryString}`
        );
    }

    const page = params.page ?? 0;
    const size = params.size ?? 20;
    const filteredTasks = filterTasks(params);
    const sortedTasks = sortTasks(filteredTasks, params.sort);

    return mockResponse(createPageResponse(sortedTasks, page, size));
}

export async function getHousekeepingTaskById(
    id: number
): Promise<HousekeepingTask> {
    if (!USE_MOCK_API) {
        return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}`);
    }

    return mockResponse(getTaskOrThrow(id));
}

export async function createHousekeepingTask(
    request: CreateHousekeepingTaskRequest
): Promise<HousekeepingTask> {
    if (!USE_MOCK_API) {
        return apiFetch<HousekeepingTask>("/api/housekeeping-tasks", {
            method: "POST",
            body: JSON.stringify(request),
        });
    }

    const room = getRoomOrThrow(request.roomId);
    const agent = request.assignedAgentId
        ? getAgentOrThrow(request.assignedAgentId)
        : null;
    const now = nowIsoDateTime();

    const createdTask: HousekeepingTask = {
        id: getNextTaskId(),
        roomId: room.id,
        roomNumber: room.roomNumber,
        reservationId: request.reservationId ?? null,
        assignedAgentId: agent?.id ?? null,
        assignedAgentName: agent?.fullName ?? null,
        type: request.type,
        status: "TODO",
        priority: request.priority,
        scheduledDate: request.scheduledDate,
        notes: request.notes ?? null,
        createdAt: now,
        updatedAt: now,
    };

    housekeepingTaskStore = [createdTask, ...housekeepingTaskStore];

    if (room.status === "AVAILABLE") {
        updateRoomStatus(room.id, "DIRTY");
    }

    return mockResponse(createdTask);
}

export async function updateHousekeepingTask(
    id: number,
    request: UpdateHousekeepingTaskRequest
): Promise<HousekeepingTask> {
    if (!USE_MOCK_API) {
        return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}`, {
            method: "PUT",
            body: JSON.stringify(request),
        });
    }

    const updatedTask = updateTask(id, (task) => {
        if (task.status === "DONE" || task.status === "CANCELLED") {
            throw new Error("Une tâche finale ne peut plus être modifiée.");
        }

        return {
            ...task,
            type: request.type ?? task.type,
            priority: request.priority ?? task.priority,
            scheduledDate: request.scheduledDate ?? task.scheduledDate,
            notes: request.notes ?? task.notes,
        };
    });

    return mockResponse(updatedTask);
}

export async function assignHousekeepingTask(
    id: number,
    request: AssignHousekeepingTaskRequest
): Promise<HousekeepingTask> {
    if (!USE_MOCK_API) {
        return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}/assign`, {
            method: "PATCH",
            body: JSON.stringify(request),
        });
    }

    const agent = getAgentOrThrow(request.assignedAgentId);
    const updatedTask = updateTask(id, (task) => {
        if (task.status === "DONE" || task.status === "CANCELLED") {
            throw new Error("Une tâche finale ne peut plus être assignée.");
        }

        return {
            ...task,
            assignedAgentId: agent.id,
            assignedAgentName: agent.fullName,
        };
    });

    return mockResponse(updatedTask);
}

export async function startHousekeepingTask(id: number): Promise<HousekeepingTask> {
    if (!USE_MOCK_API) {
        return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}/start`, {
            method: "PATCH",
        });
    }

    const updatedTask = updateTask(id, (task) => {
        if (task.status !== "TODO") {
            throw new Error("Seule une tâche à faire peut être démarrée.");
        }

        updateRoomStatus(task.roomId, "CLEANING");

        return {
            ...task,
            status: "IN_PROGRESS",
            startedAt: nowIsoDateTime(),
        };
    });

    return mockResponse(updatedTask);
}

export async function completeHousekeepingTask(
    id: number
): Promise<HousekeepingTask> {
    if (!USE_MOCK_API) {
        return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}/complete`, {
            method: "PATCH",
        });
    }

    const updatedTask = updateTask(id, (task) => {
        if (task.status !== "IN_PROGRESS") {
            throw new Error("Seule une tâche en cours peut être terminée.");
        }

        updateRoomStatus(task.roomId, "AVAILABLE");

        return {
            ...task,
            status: "DONE",
            completedAt: nowIsoDateTime(),
        };
    });

    return mockResponse(updatedTask);
}

export async function cancelHousekeepingTask(
    id: number,
    request: CancelHousekeepingTaskRequest
): Promise<HousekeepingTask> {
    if (!USE_MOCK_API) {
        return apiFetch<HousekeepingTask>(`/api/housekeeping-tasks/${id}/cancel`, {
            method: "PATCH",
            body: JSON.stringify(request),
        });
    }

    const updatedTask = updateTask(id, (task) => {
        if (task.status !== "TODO" && task.status !== "IN_PROGRESS") {
            throw new Error("Seule une tâche à faire ou en cours peut être annulée.");
        }

        return {
            ...task,
            status: "CANCELLED",
            cancelledAt: nowIsoDateTime(),
            cancellationReason: request.reason,
        };
    });

    return mockResponse(updatedTask);
}

export async function getTodayHousekeepingTasks(): Promise<HousekeepingTask[]> {
    if (!USE_MOCK_API) {
        return apiFetch<HousekeepingTask[]>("/api/housekeeping-tasks/today");
    }

    const today = todayIsoDate();
    const tasks = housekeepingTaskStore.filter(
        (task) => task.scheduledDate === today || task.scheduledDate === "2026-06-19"
    );

    return mockResponse(sortTasks(tasks, "priority,desc"));
}

export async function getHousekeepingTasksByRoomId(
    roomId: number
): Promise<RoomCleaningHistoryItem[]> {
    if (!USE_MOCK_API) {
        return apiFetch<RoomCleaningHistoryItem[]>(
            `/api/housekeeping-tasks/room/${roomId}`
        );
    }

    const history = housekeepingTaskStore
        .filter((task) => task.roomId === roomId)
        .map(toHistoryItem)
        .sort((first, second) =>
            second.scheduledDate.localeCompare(first.scheduledDate)
        );

    return mockResponse(history);
}

export async function getHousekeepingTasksByAgentId(
    agentId: number
): Promise<HousekeepingTask[]> {
    if (!USE_MOCK_API) {
        return apiFetch<HousekeepingTask[]>(
            `/api/housekeeping-tasks/agent/${agentId}`
        );
    }

    const tasks = housekeepingTaskStore.filter(
        (task) => task.assignedAgentId === agentId
    );

    return mockResponse(sortTasks(tasks, "scheduledDate,asc"));
}

export async function getHousekeepingStats(): Promise<HousekeepingStats> {
    if (!USE_MOCK_API) {
        const tasksPage = await getHousekeepingTasks({ page: 0, size: 1000 });

        return calculateStats(tasksPage.content);
    }

    return mockResponse(calculateStats(housekeepingTaskStore));
}

export async function getHousekeepingAgents(): Promise<HousekeepingAgentOption[]> {
    return mockResponse(mockHousekeepingAgents.filter((agent) => agent.active));
}

export async function getHousekeepingRooms(): Promise<HousekeepingRoomOption[]> {
    return mockResponse(housekeepingRoomStore);
}
