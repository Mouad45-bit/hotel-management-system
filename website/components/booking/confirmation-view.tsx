'use client'

import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { useEffect, useState } from 'react'
import { Check, FileSearch, Loader2 } from 'lucide-react'
import { getBookingByReferenceOnly } from '@/lib/api'
import { BookingDetails } from '@/components/booking/booking-details'
import type { Booking } from '@/lib/types'

export function ConfirmationView() {
  const params = useSearchParams()
  const ref = params.get('ref') ?? ''
  const [booking, setBooking] = useState<Booking | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    getBookingByReferenceOnly(ref).then((b) => {
      if (active) {
        setBooking(b)
        setLoading(false)
      }
    })
    return () => {
      active = false
    }
  }, [ref])

  return (
    <div className="mx-auto max-w-3xl px-6 py-20 lg:px-10">
      <div className="flex flex-col items-center text-center">
        <span className="relative flex size-24 items-center justify-center rounded-full border border-gold/40">
          <span className="absolute inset-0 animate-ping rounded-full bg-gold/10" />
          <span className="flex size-16 items-center justify-center rounded-full bg-gold text-ink">
            <Check className="size-8" strokeWidth={3} />
          </span>
        </span>
        <h1 className="mt-8 text-balance font-serif text-4xl text-cream sm:text-5xl">
          Réservation confirmée !
        </h1>
        <p className="mt-4 max-w-md text-pretty leading-relaxed text-muted-foreground">
          Merci pour votre confiance. Un email de confirmation vous a été envoyé. Nous avons hâte
          de vous accueillir à Maison Lumière.
        </p>

        {ref && (
          <div className="mt-8 rounded-2xl border border-gold/40 bg-card px-8 py-5">
            <p className="text-xs uppercase tracking-[0.25em] text-muted-foreground">
              Référence de réservation
            </p>
            <p className="mt-2 font-mono text-2xl tracking-wider text-gold">{ref}</p>
          </div>
        )}
      </div>

      <div className="mt-12">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
            <Loader2 className="size-5 animate-spin text-gold" /> Chargement du récapitulatif…
          </div>
        ) : booking ? (
          <BookingDetails booking={booking} />
        ) : (
          <div className="rounded-2xl border border-dashed border-border bg-card px-6 py-12 text-center">
            <p className="text-sm leading-relaxed text-muted-foreground">
              Le récapitulatif détaillé n&apos;est pas disponible sur cet appareil, mais votre
              réservation <span className="text-gold">{ref}</span> est bien confirmée.
            </p>
          </div>
        )}
      </div>

      <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row">
        <Link
          href="/my-booking"
          className="flex items-center gap-2 rounded-full bg-gold px-7 py-3.5 text-sm font-medium text-ink transition-colors hover:bg-gold-soft"
        >
          <FileSearch className="size-4" />
          Consulter ma réservation
        </Link>
        <Link
          href="/"
          className="rounded-full border border-border px-7 py-3.5 text-sm text-cream transition-colors hover:border-gold hover:text-gold"
        >
          Retour à l&apos;accueil
        </Link>
      </div>
    </div>
  )
}
