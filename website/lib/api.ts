import type {
  Booking,
  BookingStatus,
  Room,
  RoomSearchFilters,
} from './types'
import { ROOM_TYPE_IMAGES, ROOM_TYPE_LABELS } from './types'

const API_BASE =
  process.env.NEXT_PUBLIC_HMS_API_URL ?? 'http://localhost:8080/api/public'

function roomImage(type: string): string {
  return ROOM_TYPE_IMAGES[type] ?? '/images/room-simple.png'
}

function mapRoom(raw: Record<string, unknown>): Room {
  const type = raw.type as string
  return {
    id: String(raw.id),
    number: String(raw.number),
    type: type as Room['type'],
    floor: Number(raw.floor),
    capacity: Number(raw.capacity),
    pricePerNight: Number(raw.pricePerNight),
    image: roomImage(type),
    description: (raw.description as string) ?? '',
  }
}

function nightsBetween(checkIn: string, checkOut: string): number {
  const start = new Date(checkIn)
  const end = new Date(checkOut)
  const diff = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24))
  return Number.isFinite(diff) && diff > 0 ? diff : 1
}

/** GET /api/public/rooms/available */
export async function getRooms(filters?: RoomSearchFilters): Promise<Room[]> {
  const params = new URLSearchParams()

  if (filters?.checkIn) params.set('checkIn', filters.checkIn)
  else params.set('checkIn', new Date().toISOString().split('T')[0])

  if (filters?.checkOut) params.set('checkOut', filters.checkOut)
  else {
    const tomorrow = new Date()
    tomorrow.setDate(tomorrow.getDate() + 1)
    params.set('checkOut', tomorrow.toISOString().split('T')[0])
  }

  if (filters?.type && filters.type !== 'all') params.set('type', filters.type)

  try {
    const res = await fetch(`${API_BASE}/rooms/available?${params}`, { cache: 'no-store' })
    if (!res.ok) return []
    const data = await res.json()
    return (data as Record<string, unknown>[]).map(mapRoom)
  } catch {
    return []
  }
}

/** GET /api/public/rooms/:id */
export async function getRoomById(id: string): Promise<Room | null> {
  try {
    const res = await fetch(`${API_BASE}/rooms/${id}`, { cache: 'no-store' })
    if (!res.ok) return null
    const data = await res.json()
    return mapRoom(data)
  } catch {
    return null
  }
}

/** GET /api/public/rooms (featured — one per type) */
export async function getFeaturedRooms(): Promise<Room[]> {
  const rooms = await getRooms()
  const seen = new Set<string>()
  return rooms.filter((r) => {
    if (seen.has(r.type)) return false
    seen.add(r.type)
    return true
  }).slice(0, 4)
}

export interface CreateBookingInput {
  roomId: string
  checkIn: string
  checkOut: string
  customer: {
    firstName: string
    lastName: string
    email: string
    phone: string
    specialRequests?: string
  }
}

/** POST /api/public/book */
export async function createBooking(input: CreateBookingInput): Promise<Booking> {
  const res = await fetch(`${API_BASE}/book`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      firstName: input.customer.firstName,
      lastName: input.customer.lastName,
      email: input.customer.email,
      phone: input.customer.phone,
      roomId: Number(input.roomId),
      checkInDate: input.checkIn,
      checkOutDate: input.checkOut,
      specialRequests: input.customer.specialRequests ?? '',
    }),
  })

  if (!res.ok) {
    const err = await res.json().catch(() => null)
    throw new Error(err?.message ?? 'Erreur lors de la réservation')
  }

  const data = await res.json()
  const nights = nightsBetween(data.checkInDate, data.checkOutDate)

  const booking: Booking = {
    reference: data.reference,
    room: {
      id: input.roomId,
      number: data.roomNumber,
      type: data.roomType as Room['type'],
      floor: 0,
      capacity: 0,
      pricePerNight: data.totalPrice / nights,
      image: roomImage(data.roomType),
      description: '',
    },
    customer: {
      firstName: input.customer.firstName,
      lastName: input.customer.lastName,
      email: input.customer.email,
      phone: input.customer.phone,
      specialRequests: input.customer.specialRequests,
    },
    checkIn: data.checkInDate,
    checkOut: data.checkOutDate,
    nights,
    total: data.totalPrice,
    status: data.status as BookingStatus,
    createdAt: data.createdAt,
  }

  if (typeof window !== 'undefined') {
    window.localStorage.setItem('__hms_last_booking__', JSON.stringify(booking))
  }

  return booking
}

/** GET /api/public/booking/:ref?email=... */
export async function getBookingByReference(
  reference: string,
  email: string,
): Promise<Booking | null> {
  try {
    const res = await fetch(
      `${API_BASE}/booking/${encodeURIComponent(reference)}?email=${encodeURIComponent(email)}`,
      { cache: 'no-store' },
    )
    if (!res.ok) return null
    const data = await res.json()
    return mapBookingResponse(data)
  } catch {
    return null
  }
}

/** Récupère la dernière réservation depuis localStorage (pour la page /confirmation) */
export async function getBookingByReferenceOnly(
  reference: string,
): Promise<Booking | null> {
  if (typeof window === 'undefined') return null
  try {
    const stored = window.localStorage.getItem('__hms_last_booking__')
    if (!stored) return null
    const booking = JSON.parse(stored) as Booking
    if (booking.reference === reference) return booking
    return null
  } catch {
    return null
  }
}

function mapBookingResponse(data: Record<string, unknown>): Booking {
  const nameParts = (data.guestName as string)?.split(' ') ?? ['', '']
  const nights = Number(data.nights) || nightsBetween(data.checkInDate as string, data.checkOutDate as string)
  const total = Number(data.totalPrice)

  return {
    reference: data.reference as string,
    room: {
      id: '0',
      number: data.roomNumber as string,
      type: data.roomType as Room['type'],
      floor: 0,
      capacity: 0,
      pricePerNight: nights > 0 ? total / nights : total,
      image: roomImage(data.roomType as string),
      description: '',
    },
    customer: {
      firstName: nameParts[0],
      lastName: nameParts.slice(1).join(' '),
      email: data.guestEmail as string,
      phone: '',
      specialRequests: data.specialRequests as string,
    },
    checkIn: data.checkInDate as string,
    checkOut: data.checkOutDate as string,
    nights,
    total,
    status: data.status as BookingStatus,
    createdAt: data.createdAt as string,
  }
}

export { nightsBetween, ROOM_TYPE_LABELS }
export const PUBLIC_API_BASE = API_BASE
