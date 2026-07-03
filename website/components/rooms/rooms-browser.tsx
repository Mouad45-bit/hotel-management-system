'use client'

import { useState, useCallback } from 'react'
import { BedDouble, CalendarDays, Loader2, Search, SlidersHorizontal } from 'lucide-react'
import { RoomCard } from '@/components/room-card'
import { ScrollReveal } from '@/components/scroll-reveal'
import { getRooms } from '@/lib/api'
import type { Room, RoomType } from '@/lib/types'

const TYPES: Array<{ value: RoomType | 'all'; label: string }> = [
  { value: 'all', label: 'Tous les types' },
  { value: 'SINGLE', label: 'Simple' },
  { value: 'DOUBLE', label: 'Double' },
  { value: 'TWIN', label: 'Twin' },
  { value: 'SUITE', label: 'Suite' },
  { value: 'DELUXE', label: 'Deluxe' },
  { value: 'FAMILY', label: 'Familiale' },
]

const fieldClass =
  'w-full rounded-xl border border-border bg-background px-4 py-3 text-sm text-cream outline-none transition-colors focus:border-gold [color-scheme:dark]'
const labelClass =
  'mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.15em] text-muted-foreground'

export function RoomsBrowser({ rooms: initialRooms }: { rooms: Room[] }) {
  const today = new Date().toISOString().split('T')[0]
  const tomorrow = new Date(Date.now() + 86400000).toISOString().split('T')[0]

  const [checkIn, setCheckIn] = useState(today)
  const [checkOut, setCheckOut] = useState(tomorrow)
  const [type, setType] = useState<RoomType | 'all'>('all')
  const [rooms, setRooms] = useState(initialRooms)
  const [loading, setLoading] = useState(false)
  const [searched, setSearched] = useState(false)

  const handleSearch = useCallback(async () => {
    if (!checkIn || !checkOut) return
    setLoading(true)
    try {
      const results = await getRooms({
        checkIn,
        checkOut,
        type: type === 'all' ? undefined : type,
      })
      setRooms(results)
      setSearched(true)
    } catch {
      setRooms([])
    } finally {
      setLoading(false)
    }
  }, [checkIn, checkOut, type])

  return (
    <div className="mx-auto max-w-7xl px-6 py-16 lg:px-10 lg:py-20">
      {/* Search bar */}
      <ScrollReveal className="rounded-3xl border border-border bg-card p-6 lg:p-8">
        <div className="grid gap-5 md:grid-cols-4">
          <div>
            <label htmlFor="checkin" className={labelClass}>
              <CalendarDays className="size-4 text-gold" /> Arrivée
            </label>
            <input
              id="checkin"
              type="date"
              min={today}
              value={checkIn}
              onChange={(e) => setCheckIn(e.target.value)}
              className={fieldClass}
            />
          </div>
          <div>
            <label htmlFor="checkout" className={labelClass}>
              <CalendarDays className="size-4 text-gold" /> Départ
            </label>
            <input
              id="checkout"
              type="date"
              min={checkIn || today}
              value={checkOut}
              onChange={(e) => setCheckOut(e.target.value)}
              className={fieldClass}
            />
          </div>
          <div>
            <label htmlFor="type" className={labelClass}>
              <BedDouble className="size-4 text-gold" /> Type de chambre
            </label>
            <select
              id="type"
              value={type}
              onChange={(e) => setType(e.target.value as RoomType | 'all')}
              className={fieldClass}
            >
              {TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-end">
            <button
              type="button"
              onClick={handleSearch}
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gold px-6 py-3 text-sm font-medium text-ink transition-colors hover:bg-gold-soft disabled:opacity-60"
            >
              {loading ? (
                <><Loader2 className="size-4 animate-spin" /> Recherche…</>
              ) : (
                <><Search className="size-4" /> Rechercher</>
              )}
            </button>
          </div>
        </div>
      </ScrollReveal>

      {/* Results */}
      <div className="mt-10 flex items-center justify-between">
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <SlidersHorizontal className="size-4 text-gold" />
          {rooms.length} chambre{rooms.length > 1 ? 's' : ''} disponible
          {rooms.length > 1 ? 's' : ''}
        </p>
      </div>

      {rooms.length > 0 ? (
        <div className="mt-8 grid gap-8 sm:grid-cols-2 lg:grid-cols-3">
          {rooms.map((room, i) => (
            <ScrollReveal key={room.id} delay={(i % 3) * 100}>
              <RoomCard room={room} showDetails />
            </ScrollReveal>
          ))}
        </div>
      ) : (
        <div className="mt-12 flex flex-col items-center justify-center rounded-3xl border border-dashed border-border bg-card px-6 py-20 text-center">
          <span className="flex size-16 items-center justify-center rounded-full border border-gold/40 text-gold">
            <BedDouble className="size-7" />
          </span>
          <h3 className="mt-6 font-serif text-2xl text-cream">
            {searched ? 'Aucune chambre disponible' : 'Lancez une recherche'}
          </h3>
          <p className="mt-3 max-w-md text-sm leading-relaxed text-muted-foreground">
            {searched
              ? "Aucune chambre ne correspond à vos critères pour ces dates. Essayez d'ajuster le type de chambre ou vos dates de séjour."
              : 'Sélectionnez vos dates et cliquez sur Rechercher pour voir les chambres disponibles.'}
          </p>
        </div>
      )}
    </div>
  )
}
