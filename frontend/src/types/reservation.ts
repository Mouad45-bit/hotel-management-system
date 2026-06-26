export type ReservationStatus = 'CREATED' | 'CONFIRMED' | 'CHECKED_IN' | 'CHECKED_OUT' | 'CANCELLED' | 'NO_SHOW';

export interface Reservation {
    id: number;
    roomId: number;
    clientId: number;
    checkInDate: string;
    checkOutDate: string;
    status: ReservationStatus;
    totalPrice: number;
    notes?: string;
    active: boolean;
    createdAt?: string;
    updatedAt?: string;
}
