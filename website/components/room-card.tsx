import Image from 'next/image'
import Link from 'next/link'
import { ArrowRight, Layers, Users } from 'lucide-react'
import type { Room } from '@/lib/types'
import { ROOM_TYPE_LABELS } from '@/lib/types'

interface RoomCardProps {
  room: Room
  showDetails?: boolean
}

export function RoomCard({ room, showDetails = false }: RoomCardProps) {
  return (
    <article className="group overflow-hidden rounded-2xl border border-border bg-card transition-colors hover:border-gold/60">
      <div className="relative aspect-[4/3] overflow-hidden">
        <Image
          src={room.image || '/placeholder.svg'}
          alt={`Chambre ${ROOM_TYPE_LABELS[room.type] ?? room.type} n°${room.number}`}
          fill
          sizes="(max-width: 768px) 100vw, 33vw"
          className="object-cover transition-transform duration-700 group-hover:scale-105"
        />
        <div className="absolute inset-0 bg-gradient-to-t from-ink/70 via-transparent to-transparent" />
        <span className="absolute left-4 top-4 rounded-full bg-background/80 px-3 py-1 text-xs uppercase tracking-[0.2em] text-gold backdrop-blur">
          {ROOM_TYPE_LABELS[room.type] ?? room.type}
        </span>
      </div>

      <div className="p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="font-serif text-xl text-cream">Chambre {ROOM_TYPE_LABELS[room.type] ?? room.type}</h3>
            <p className="mt-1 text-sm text-muted-foreground">N° {room.number}</p>
          </div>
          <div className="text-right">
            <p className="font-serif text-2xl text-gold">{room.pricePerNight} DH</p>
            <p className="text-xs text-muted-foreground">/ nuit</p>
          </div>
        </div>

        <div className="mt-4 flex items-center gap-5 text-sm text-muted-foreground">
          <span className="flex items-center gap-2">
            <Users className="size-4 text-gold" />
            {room.capacity} {room.capacity > 1 ? 'personnes' : 'personne'}
          </span>
          <span className="flex items-center gap-2">
            <Layers className="size-4 text-gold" />
            Étage {room.floor}
          </span>
        </div>

        {showDetails && (
          <p className="mt-4 text-sm leading-relaxed text-muted-foreground">{room.description}</p>
        )}

        <Link
          href={`/book?roomId=${room.id}`}
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-full bg-gold px-6 py-3 text-sm font-medium text-ink transition-colors hover:bg-gold-soft"
        >
          Réserver
          <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
        </Link>
      </div>
    </article>
  )
}
