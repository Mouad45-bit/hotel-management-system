export type RoomType = 'SINGLE' | 'DOUBLE' | 'TWIN' | 'SUITE' | 'FAMILY' | 'DELUXE';

export type RoomStatus = 'AVAILABLE' | 'RESERVED' | 'OCCUPIED' | 'CLEANING' | 'MAINTENANCE' | 'OUT_OF_SERVICE';

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
