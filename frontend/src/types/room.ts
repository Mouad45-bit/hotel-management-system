// frontend/src/types/room.ts

export const ROOM_TYPES = [
    "SINGLE",
    "DOUBLE",
    "TWIN",
    "SUITE",
    "FAMILY",
    "DELUXE",
] as const;

export type RoomType = (typeof ROOM_TYPES)[number];


export const ROOM_STATUSES = [
    "AVAILABLE",
    "RESERVED",
    "OCCUPIED",
    "CLEANING",
    "MAINTENANCE",
    "OUT_OF_SERVICE",
] as const;

export type RoomStatus = (typeof ROOM_STATUSES)[number];


export interface Room {
    id: number;
    number: string;
    floor: number;
    type: RoomType;
    pricePerNight: number;
    capacity: number;
    status: RoomStatus;
    description?: string;
    active: boolean;
    createdAt: string;
    updatedAt: string;
}

export interface CreateRoomRequest {
    number: string;
    floor: number;
    type: RoomType;
    pricePerNight: number;
    capacity: number;
    status: RoomStatus;
    description?: string;
}

export type UpdateRoomRequest = CreateRoomRequest;

export interface UpdateRoomStatusRequest {
    status: RoomStatus;
}


export interface RoomSearchParams {
    number?: string;
    type?: RoomType | "";
    status?: RoomStatus | "";
    floor?: number;
    capacity?: number;
}

export interface RoomFiltersState {
    number: string;
    type: RoomType | "";
    status: RoomStatus | "";
    floor: string;
    capacity: string;
}

export interface RoomStats {
    total: number;
    available: number;
    occupied: number;
    reserved: number;
    cleaning: number;
    maintenance: number;
    outOfService: number;
}


export const ROOM_TYPE_LABELS: Record<RoomType, string> = {
    SINGLE: "Simple",
    DOUBLE: "Double",
    TWIN: "Twin",
    SUITE: "Suite",
    FAMILY: "Familiale",
    DELUXE: "Deluxe",
};

export const ROOM_STATUS_LABELS: Record<RoomStatus, string> = {
    AVAILABLE: "Disponible",
    RESERVED: "Réservée",
    OCCUPIED: "Occupée",
    CLEANING: "Nettoyage",
    MAINTENANCE: "Maintenance",
    OUT_OF_SERVICE: "Hors service",
};

export const ROOM_STATUS_BADGE_CLASSES: Record<RoomStatus, string> = {
    AVAILABLE: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
    RESERVED: "bg-blue-50 text-blue-700 ring-blue-600/20",
    OCCUPIED: "bg-orange-50 text-orange-700 ring-orange-600/20",
    CLEANING: "bg-violet-50 text-violet-700 ring-violet-600/20",
    MAINTENANCE: "bg-amber-50 text-amber-700 ring-amber-600/20",
    OUT_OF_SERVICE: "bg-zinc-100 text-zinc-700 ring-zinc-500/20",
};

export const DEFAULT_ROOM_FILTERS: RoomFiltersState = {
    number: "",
    type: "",
    status: "",
    floor: "",
    capacity: "",
};
