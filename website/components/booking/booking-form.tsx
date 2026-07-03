'use client'

import Image from 'next/image'
import { useRouter } from 'next/navigation'
import { useMemo, useState } from 'react'
import {
  CalendarDays,
  CreditCard,
  Loader2,
  Lock,
  Moon,
  ShieldCheck,
  Users,
} from 'lucide-react'
import { createBooking, nightsBetween } from '@/lib/api'
import type { Room } from '@/lib/types'
import { ROOM_TYPE_LABELS } from '@/lib/types'

const fieldClass =
  'w-full rounded-xl border border-border bg-background px-4 py-3 text-sm text-cream outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-gold [color-scheme:dark]'
const labelClass = 'mb-2 block text-xs uppercase tracking-[0.15em] text-muted-foreground'

function formatDate(value: string) {
  if (!value) return '—'
  return new Date(value).toLocaleDateString('fr-FR', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  })
}

export function BookingForm({ room }: { room: Room }) {
  const router = useRouter()
  const today = new Date().toISOString().split('T')[0]
  const tomorrow = new Date(Date.now() + 86400000).toISOString().split('T')[0]

  const [checkIn, setCheckIn] = useState(today)
  const [checkOut, setCheckOut] = useState(tomorrow)
  const [form, setForm] = useState({
    firstName: '',
    lastName: '',
    email: '',
    phone: '',
    specialRequests: '',
    cardNumber: '',
    cardExpiry: '',
    cardCvv: '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const nights = useMemo(() => nightsBetween(checkIn, checkOut), [checkIn, checkOut])
  const total = nights * room.pricePerNight

  const update = (key: keyof typeof form) => (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
  ) => setForm((f) => ({ ...f, [key]: e.target.value }))

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (new Date(checkOut) <= new Date(checkIn)) {
      setError('La date de départ doit être postérieure à la date d\'arrivée.')
      return
    }
    setSubmitting(true)
    try {
      const booking = await createBooking({
        roomId: room.id,
        checkIn,
        checkOut,
        customer: {
          firstName: form.firstName,
          lastName: form.lastName,
          email: form.email,
          phone: form.phone,
          specialRequests: form.specialRequests,
        },
      })
      router.push(`/confirmation?ref=${booking.reference}&email=${encodeURIComponent(form.email)}`)
    } catch {
      setError('Une erreur est survenue. Veuillez réessayer.')
      setSubmitting(false)
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="mx-auto grid max-w-7xl gap-10 px-6 py-16 lg:grid-cols-[1.5fr_1fr] lg:px-10 lg:py-20"
    >
      {/* Left: form */}
      <div className="space-y-10">
        {/* Dates */}
        <fieldset className="rounded-2xl border border-border bg-card p-6 lg:p-8">
          <legend className="px-2 font-serif text-xl text-cream">Votre séjour</legend>
          <div className="mt-4 grid gap-5 sm:grid-cols-2">
            <div>
              <label htmlFor="ci" className={labelClass}>Date d&apos;arrivée</label>
              <input id="ci" type="date" min={today} value={checkIn}
                onChange={(e) => setCheckIn(e.target.value)} className={fieldClass} required />
            </div>
            <div>
              <label htmlFor="co" className={labelClass}>Date de départ</label>
              <input id="co" type="date" min={checkIn} value={checkOut}
                onChange={(e) => setCheckOut(e.target.value)} className={fieldClass} required />
            </div>
          </div>
        </fieldset>

        {/* Customer */}
        <fieldset className="rounded-2xl border border-border bg-card p-6 lg:p-8">
          <legend className="px-2 font-serif text-xl text-cream">Vos informations</legend>
          <div className="mt-4 grid gap-5 sm:grid-cols-2">
            <div>
              <label htmlFor="fn" className={labelClass}>Prénom</label>
              <input id="fn" value={form.firstName} onChange={update('firstName')}
                className={fieldClass} placeholder="Jean" required />
            </div>
            <div>
              <label htmlFor="ln" className={labelClass}>Nom</label>
              <input id="ln" value={form.lastName} onChange={update('lastName')}
                className={fieldClass} placeholder="Dupont" required />
            </div>
            <div>
              <label htmlFor="em" className={labelClass}>Email</label>
              <input id="em" type="email" value={form.email} onChange={update('email')}
                className={fieldClass} placeholder="jean.dupont@email.com" required />
            </div>
            <div>
              <label htmlFor="ph" className={labelClass}>Téléphone</label>
              <input id="ph" type="tel" value={form.phone} onChange={update('phone')}
                className={fieldClass} placeholder="+212 6 12 34 56 78" required />
            </div>
          </div>
          <div className="mt-5">
            <label htmlFor="sr" className={labelClass}>Demandes spéciales</label>
            <textarea id="sr" value={form.specialRequests} onChange={update('specialRequests')}
              rows={3} className={`${fieldClass} resize-none`}
              placeholder="Lit supplémentaire, étage élevé, allergies…" />
          </div>
        </fieldset>

        {/* Payment (simulated) */}
        <fieldset className="rounded-2xl border border-border bg-card p-6 lg:p-8">
          <legend className="px-2 font-serif text-xl text-cream">Paiement</legend>
          <p className="mt-1 flex items-center gap-2 px-2 text-xs text-muted-foreground">
            <Lock className="size-3.5 text-gold" />
            Paiement simulé — aucune transaction réelle n&apos;est effectuée.
          </p>
          <div className="mt-5 space-y-5">
            <div>
              <label htmlFor="cn" className={labelClass}>Numéro de carte</label>
              <div className="relative">
                <CreditCard className="pointer-events-none absolute left-4 top-1/2 size-4 -translate-y-1/2 text-gold" />
                <input id="cn" value={form.cardNumber} onChange={update('cardNumber')}
                  inputMode="numeric" maxLength={19} className={`${fieldClass} pl-11`}
                  placeholder="4242 4242 4242 4242" required />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-5">
              <div>
                <label htmlFor="ce" className={labelClass}>Expiration</label>
                <input id="ce" value={form.cardExpiry} onChange={update('cardExpiry')}
                  maxLength={5} className={fieldClass} placeholder="MM/AA" required />
              </div>
              <div>
                <label htmlFor="cv" className={labelClass}>CVV</label>
                <input id="cv" value={form.cardCvv} onChange={update('cardCvv')}
                  inputMode="numeric" maxLength={4} className={fieldClass} placeholder="123" required />
              </div>
            </div>
          </div>
        </fieldset>

        {error && (
          <p className="rounded-xl border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {error}
          </p>
        )}
      </div>

      {/* Right: summary */}
      <aside className="lg:sticky lg:top-28 lg:self-start">
        <div className="overflow-hidden rounded-2xl border border-border bg-card">
          <div className="relative aspect-[4/3]">
            <Image src={room.image || '/placeholder.svg'} alt={`Chambre ${ROOM_TYPE_LABELS[room.type] ?? room.type}`} fill
              sizes="(max-width: 1024px) 100vw, 33vw" className="object-cover" />
            <span className="absolute left-4 top-4 rounded-full bg-background/80 px-3 py-1 text-xs uppercase tracking-[0.2em] text-gold backdrop-blur">
              {ROOM_TYPE_LABELS[room.type] ?? room.type}
            </span>
          </div>
          <div className="p-6">
            <h3 className="font-serif text-2xl text-cream">Chambre {ROOM_TYPE_LABELS[room.type] ?? room.type}</h3>
            <p className="mt-1 text-sm text-muted-foreground">N° {room.number} · Étage {room.floor}</p>

            <div className="mt-5 space-y-3 text-sm">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="flex items-center gap-2"><CalendarDays className="size-4 text-gold" /> Arrivée</span>
                <span className="text-cream">{formatDate(checkIn)}</span>
              </div>
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="flex items-center gap-2"><CalendarDays className="size-4 text-gold" /> Départ</span>
                <span className="text-cream">{formatDate(checkOut)}</span>
              </div>
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="flex items-center gap-2"><Moon className="size-4 text-gold" /> Nuits</span>
                <span className="text-cream">{nights}</span>
              </div>
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="flex items-center gap-2"><Users className="size-4 text-gold" /> Capacité</span>
                <span className="text-cream">{room.capacity} pers.</span>
              </div>
            </div>

            <div className="mt-6 space-y-3 border-t border-border pt-6 text-sm">
              <div className="flex items-center justify-between text-muted-foreground">
                <span>{room.pricePerNight} DH × {nights} nuit{nights > 1 ? 's' : ''}</span>
                <span className="text-cream">{total} DH</span>
              </div>
              <div className="flex items-center justify-between border-t border-border pt-4">
                <span className="font-serif text-lg text-cream">Total</span>
                <span className="font-serif text-2xl text-gold">{total} DH</span>
              </div>
            </div>

            <button type="submit" disabled={submitting}
              className="mt-6 flex w-full items-center justify-center gap-2 rounded-full bg-gold px-6 py-4 text-sm font-medium text-ink transition-colors hover:bg-gold-soft disabled:opacity-60">
              {submitting ? (
                <><Loader2 className="size-4 animate-spin" /> Traitement…</>
              ) : (
                <>Confirmer et payer {total} DH</>
              )}
            </button>
            <p className="mt-4 flex items-center justify-center gap-2 text-xs text-muted-foreground">
              <ShieldCheck className="size-3.5 text-gold" />
              Annulation gratuite jusqu&apos;à 48h avant l&apos;arrivée
            </p>
          </div>
        </div>
      </aside>
    </form>
  )
}
