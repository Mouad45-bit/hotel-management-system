export type RoomType =
| "SINGLE"
| "DOUBLE"
| "TWIN"
| "SUITE"
| "FAMILY"
| "DELUXE";

export type RoomStatus =
| "AVAILABLE"
| "RESERVED"
| "OCCUPIED"
| "CLEANING"
| "MAINTENANCE"
| "OUT_OF_SERVICE";

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

export interface UpdateRoomRequest extends CreateRoomRequest {}

export interface UpdateRoomStatusRequest {
status: RoomStatus;
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

export interface RoomSearchParams {
number?: string;
type?: RoomType;
status?: RoomStatus;
floor?: number;
capacity?: number;
}
