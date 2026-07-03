import Image from 'next/image'
import { CalendarDays, Moon, User } from 'lucide-react'
import type { Booking } from '@/lib/types'
import { ROOM_TYPE_LABELS } from '@/lib/types'

function formatDate(value: string) {
  return new Date(value).toLocaleDateString('fr-FR', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  })
}

const STATUS_LABEL: Record<string, string> = {
  CONFIRMED: 'Confirmée',
  CREATED: 'En attente',
  CHECKED_IN: 'En cours',
  CHECKED_OUT: 'Terminée',
  CANCELLED: 'Annulée',
  NO_SHOW: 'No-show',
}

export function BookingDetails({ booking }: { booking: Booking }) {
  return (
    <div className="overflow-hidden rounded-2xl border border-border bg-card">
      <div className="grid md:grid-cols-[200px_1fr]">
        <div className="relative aspect-[4/3] md:aspect-auto">
          <Image
            src={booking.room.image || '/placeholder.svg'}
            alt={`Chambre ${ROOM_TYPE_LABELS[booking.room.type] ?? booking.room.type}`}
            fill
            sizes="200px"
            className="object-cover"
          />
        </div>
        <div className="p-6 lg:p-8">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="font-serif text-2xl text-cream">Chambre {ROOM_TYPE_LABELS[booking.room.type] ?? booking.room.type}</h3>
              <p className="mt-1 text-sm text-muted-foreground">
                N° {booking.room.number}{booking.room.floor > 0 && ` · Étage ${booking.room.floor}`}
              </p>
            </div>
            <span className="rounded-full border border-gold/40 px-3 py-1 text-xs uppercase tracking-[0.15em] text-gold">
              {STATUS_LABEL[booking.status]}
            </span>
          </div>

          <div className="mt-6 grid gap-4 sm:grid-cols-2">
            <Detail icon={CalendarDays} label="Arrivée" value={formatDate(booking.checkIn)} />
            <Detail icon={CalendarDays} label="Départ" value={formatDate(booking.checkOut)} />
            <Detail icon={Moon} label="Nuits" value={`${booking.nights}`} />
            <Detail
              icon={User}
              label="Client"
              value={`${booking.customer.firstName} ${booking.customer.lastName}`}
            />
          </div>

          <div className="mt-6 flex items-center justify-between border-t border-border pt-6">
            <span className="text-sm text-muted-foreground">Total payé</span>
            <span className="font-serif text-2xl text-gold">{booking.total} DH</span>
          </div>
        </div>
      </div>
    </div>
  )
}

function Detail({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof CalendarDays
  label: string
  value: string
}) {
  return (
    <div className="flex items-center gap-3">
      <span className="flex size-9 items-center justify-center rounded-full border border-border text-gold">
        <Icon className="size-4" />
      </span>
      <div>
        <p className="text-xs uppercase tracking-[0.15em] text-muted-foreground">{label}</p>
        <p className="text-sm text-cream">{value}</p>
      </div>
    </div>
  )
}
