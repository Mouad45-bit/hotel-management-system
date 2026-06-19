export const HOUSEKEEPING_TASK_STATUSES = [
    "TODO",
    "IN_PROGRESS",
    "DONE",
    "CANCELLED",
] as const;

export type HousekeepingTaskStatus =
    (typeof HOUSEKEEPING_TASK_STATUSES)[number];

export const HOUSEKEEPING_TASK_TYPES = [
    "STANDARD_CLEANING",
    "DEEP_CLEANING",
    "INSPECTION",
    "LIGHT_MAINTENANCE",
] as const;

export type HousekeepingTaskType = (typeof HOUSEKEEPING_TASK_TYPES)[number];

export const PRIORITIES = ["LOW", "MEDIUM", "HIGH", "URGENT"] as const;

export type Priority = (typeof PRIORITIES)[number];

export type HousekeepingStatusFilter = HousekeepingTaskStatus | "ALL";

export type HousekeepingTaskTypeFilter = HousekeepingTaskType | "ALL";

export type PriorityFilter = Priority | "ALL";

export interface HousekeepingTask {
    id: number;
    roomId: number;
    roomNumber: string;
    reservationId?: number | null;
    assignedAgentId?: number | null;
    assignedAgentName?: string | null;
    type: HousekeepingTaskType;
    status: HousekeepingTaskStatus;
    priority: Priority;
    scheduledDate: string;
    startedAt?: string | null;
    completedAt?: string | null;
    cancelledAt?: string | null;
    cancellationReason?: string | null;
    notes?: string | null;
    createdAt: string;
    updatedAt: string;
}

export interface HousekeepingTaskFiltersState {
    status: HousekeepingStatusFilter;
    type: HousekeepingTaskTypeFilter;
    priority: PriorityFilter;
    roomId: string;
    agentId: string;
    scheduledDate: string;
}

export interface HousekeepingTaskSearchParams {
    status?: HousekeepingTaskStatus;
    type?: HousekeepingTaskType;
    priority?: Priority;
    roomId?: number;
    agentId?: number;
    scheduledDate?: string;
    page?: number;
    size?: number;
    sort?: string;
}

export interface HousekeepingStats {
    total: number;
    todo: number;
    inProgress: number;
    done: number;
    cancelled: number;
    urgent: number;
    unassigned: number;
}

export interface CreateHousekeepingTaskRequest {
    roomId: number;
    reservationId?: number;
    assignedAgentId?: number;
    type: HousekeepingTaskType;
    priority: Priority;
    scheduledDate: string;
    notes?: string;
}

export interface UpdateHousekeepingTaskRequest {
    type?: HousekeepingTaskType;
    priority?: Priority;
    scheduledDate?: string;
    notes?: string;
}

export interface AssignHousekeepingTaskRequest {
    assignedAgentId: number;
}

export interface CancelHousekeepingTaskRequest {
    reason: string;
}

export interface PageResponse<T> {
    content: T[];
    page: number;
    size: number;
    totalElements: number;
    totalPages: number;
    last: boolean;
}

export interface RoomCleaningHistoryItem extends HousekeepingTask {
    durationMinutes?: number | null;
}

export interface HousekeepingAgentOption {
    id: number;
    fullName: string;
    role: "HOUSEKEEPING_AGENT" | "HOUSEKEEPING_SUPERVISOR";
    active: boolean;
}

export interface HousekeepingRoomOption {
    id: number;
    roomNumber: string;
    floor: number;
    status: "AVAILABLE" | "OCCUPIED" | "DIRTY" | "CLEANING" | "MAINTENANCE";
}

export const HOUSEKEEPING_STATUS_LABELS: Record<HousekeepingTaskStatus, string> = {
    TODO: "À faire",
    IN_PROGRESS: "En cours",
    DONE: "Terminée",
    CANCELLED: "Annulée",
};

export const HOUSEKEEPING_STATUS_FILTER_LABELS: Record<
    HousekeepingStatusFilter,
    string
> = {
    ALL: "Tous les statuts",
    TODO: "À faire",
    IN_PROGRESS: "En cours",
    DONE: "Terminée",
    CANCELLED: "Annulée",
};

export const HOUSEKEEPING_TYPE_LABELS: Record<HousekeepingTaskType, string> = {
    STANDARD_CLEANING: "Nettoyage standard",
    DEEP_CLEANING: "Nettoyage approfondi",
    INSPECTION: "Inspection",
    LIGHT_MAINTENANCE: "Maintenance légère",
};

export const HOUSEKEEPING_TYPE_FILTER_LABELS: Record<
    HousekeepingTaskTypeFilter,
    string
> = {
    ALL: "Tous les types",
    STANDARD_CLEANING: "Nettoyage standard",
    DEEP_CLEANING: "Nettoyage approfondi",
    INSPECTION: "Inspection",
    LIGHT_MAINTENANCE: "Maintenance légère",
};

export const PRIORITY_LABELS: Record<Priority, string> = {
    LOW: "Basse",
    MEDIUM: "Moyenne",
    HIGH: "Haute",
    URGENT: "Urgente",
};

export const PRIORITY_FILTER_LABELS: Record<PriorityFilter, string> = {
    ALL: "Toutes les priorités",
    LOW: "Basse",
    MEDIUM: "Moyenne",
    HIGH: "Haute",
    URGENT: "Urgente",
};

export const HOUSEKEEPING_STATUS_BADGE_CLASSES: Record<
    HousekeepingTaskStatus,
    string
> = {
    TODO: "bg-zinc-100 text-zinc-700 ring-zinc-200",
    IN_PROGRESS: "bg-blue-50 text-blue-700 ring-blue-200",
    DONE: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    CANCELLED: "bg-red-50 text-red-700 ring-red-200",
};

export const HOUSEKEEPING_TYPE_BADGE_CLASSES: Record<
    HousekeepingTaskType,
    string
> = {
    STANDARD_CLEANING: "bg-stone-50 text-stone-700 ring-stone-200",
    DEEP_CLEANING: "bg-purple-50 text-purple-700 ring-purple-200",
    INSPECTION: "bg-sky-50 text-sky-700 ring-sky-200",
    LIGHT_MAINTENANCE: "bg-amber-50 text-amber-700 ring-amber-200",
};

export const PRIORITY_BADGE_CLASSES: Record<Priority, string> = {
    LOW: "bg-zinc-100 text-zinc-700 ring-zinc-200",
    MEDIUM: "bg-blue-50 text-blue-700 ring-blue-200",
    HIGH: "bg-orange-50 text-orange-700 ring-orange-200",
    URGENT: "bg-red-50 text-red-700 ring-red-200",
};

export const DEFAULT_HOUSEKEEPING_FILTERS: HousekeepingTaskFiltersState = {
    status: "ALL",
    type: "ALL",
    priority: "ALL",
    roomId: "",
    agentId: "",
    scheduledDate: "",
};
