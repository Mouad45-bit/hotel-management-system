export type RoomType = 'SINGLE' | 'DOUBLE' | 'TWIN' | 'SUITE' | 'FAMILY' | 'DELUXE'

export const ROOM_TYPE_LABELS: Record<string, string> = {
  SINGLE: 'Simple',
  DOUBLE: 'Double',
  TWIN: 'Twin',
  SUITE: 'Suite',
  FAMILY: 'Familiale',
  DELUXE: 'Deluxe',
}

export const ROOM_TYPE_IMAGES: Record<string, string> = {
  SINGLE: '/images/room-simple.png',
  DOUBLE: '/images/room-double.png',
  TWIN: '/images/room-double.png',
  SUITE: '/images/room-suite.png',
  FAMILY: '/images/room-double.png',
  DELUXE: '/images/room-deluxe.png',
}

export interface Room {
  id: string
  number: string
  type: RoomType
  floor: number
  capacity: number
  pricePerNight: number
  image: string
  description: string
}

export interface BookingDraft {
  roomId: string
  checkIn: string
  checkOut: string
}

export interface Customer {
  firstName: string
  lastName: string
  email: string
  phone: string
  specialRequests?: string
}

export type BookingStatus = 'CONFIRMED' | 'CREATED' | 'CHECKED_IN' | 'CHECKED_OUT' | 'CANCELLED' | 'NO_SHOW'

export interface Booking {
  reference: string
  room: Room
  customer: Customer
  checkIn: string
  checkOut: string
  nights: number
  total: number
  status: BookingStatus
  createdAt: string
}

export interface RoomSearchFilters {
  checkIn?: string
  checkOut?: string
  type?: RoomType | 'all'
}
