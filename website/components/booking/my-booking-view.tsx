'use client'

import { useState } from 'react'
import { Hash, Loader2, Mail, Search } from 'lucide-react'
import { getBookingByReference } from '@/lib/api'
import { BookingDetails } from '@/components/booking/booking-details'
import type { Booking } from '@/lib/types'

const fieldClass =
  'w-full rounded-xl border border-border bg-background px-4 py-3 pl-11 text-sm text-cream outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-gold'
const labelClass = 'mb-2 block text-xs uppercase tracking-[0.15em] text-muted-foreground'

export function MyBookingView() {
  const [reference, setReference] = useState('')
  const [email, setEmail] = useState('')
  const [booking, setBooking] = useState<Booking | null>(null)
  const [loading, setLoading] = useState(false)
  const [searched, setSearched] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setSearched(false)
    const result = await getBookingByReference(reference.trim(), email.trim())
    setBooking(result)
    setSearched(true)
    setLoading(false)
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-16 lg:px-10 lg:py-20">
      <form onSubmit={handleSubmit} className="rounded-2xl border border-border bg-card p-6 lg:p-8">
        <div className="grid gap-5 sm:grid-cols-2">
          <div>
            <label htmlFor="ref" className={labelClass}>Référence</label>
            <div className="relative">
              <Hash className="pointer-events-none absolute left-4 top-1/2 size-4 -translate-y-1/2 text-gold" />
              <input id="ref" value={reference} onChange={(e) => setReference(e.target.value)}
                className={fieldClass} placeholder="HMS-2026-123456" required />
            </div>
          </div>
          <div>
            <label htmlFor="mail" className={labelClass}>Email</label>
            <div className="relative">
              <Mail className="pointer-events-none absolute left-4 top-1/2 size-4 -translate-y-1/2 text-gold" />
              <input id="mail" type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                className={fieldClass} placeholder="jean.dupont@email.com" required />
            </div>
          </div>
        </div>
        <button type="submit" disabled={loading}
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-full bg-gold px-6 py-3.5 text-sm font-medium text-ink transition-colors hover:bg-gold-soft disabled:opacity-60 sm:w-auto sm:px-10">
          {loading ? <><Loader2 className="size-4 animate-spin" /> Recherche…</>
            : <><Search className="size-4" /> Consulter</>}
        </button>
      </form>

      <div className="mt-10">
        {booking && <BookingDetails booking={booking} />}
        {searched && !booking && (
          <div className="rounded-2xl border border-dashed border-border bg-card px-6 py-14 text-center">
            <h3 className="font-serif text-2xl text-cream">Réservation introuvable</h3>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              Aucune réservation ne correspond à cette référence et cet email. Vérifiez vos
              informations et réessayez.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
