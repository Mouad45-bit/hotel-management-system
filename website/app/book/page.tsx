import Link from 'next/link'
import { ArrowLeft, BedDouble } from 'lucide-react'
import { Navbar } from '@/components/navbar'
import { Footer } from '@/components/footer'
import { PageBanner } from '@/components/page-banner'
import { BookingForm } from '@/components/booking/booking-form'
import { getRoomById } from '@/lib/api'

export const metadata = {
  title: 'Réservation — Maison Lumière',
}

export default async function BookPage({
  searchParams,
}: {
  searchParams: Promise<{ roomId?: string }>
}) {
  const { roomId } = await searchParams
  const room = roomId ? await getRoomById(roomId) : null

  return (
    <>
      <Navbar />
      <main>
        <PageBanner
          eyebrow="Réservation"
          title="Finalisez votre séjour"
          description="Quelques informations et votre chambre est à vous. Le raffinement vous attend."
        />

        {room ? (
          <BookingForm room={room} />
        ) : (
          <div className="mx-auto flex max-w-2xl flex-col items-center px-6 py-24 text-center">
            <span className="flex size-16 items-center justify-center rounded-full border border-gold/40 text-gold">
              <BedDouble className="size-7" />
            </span>
            <h2 className="mt-6 font-serif text-2xl text-cream">Aucune chambre sélectionnée</h2>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              Veuillez choisir une chambre parmi nos disponibilités pour poursuivre votre réservation.
            </p>
            <Link
              href="/rooms"
              className="mt-7 flex items-center gap-2 rounded-full bg-gold px-6 py-3 text-sm font-medium text-ink transition-colors hover:bg-gold-soft"
            >
              <ArrowLeft className="size-4" />
              Voir les chambres
            </Link>
          </div>
        )}
      </main>
      <Footer />
    </>
  )
}
