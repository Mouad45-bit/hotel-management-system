import Link from 'next/link'
import { ArrowRight } from 'lucide-react'
import { getFeaturedRooms } from '@/lib/api'
import { RoomCard } from '@/components/room-card'
import { SectionHeading } from '@/components/section-heading'
import { ScrollReveal } from '@/components/scroll-reveal'

export async function FeaturedRooms() {
  const rooms = await getFeaturedRooms()

  return (
    <section id="chambres" className="bg-background py-24 lg:py-32">
      <div className="mx-auto max-w-7xl px-6 lg:px-10">
        <ScrollReveal>
          <SectionHeading
            eyebrow="Nos chambres"
            title="Des espaces pensés pour votre confort"
            description="De la chambre intimiste à la suite panoramique, chaque chambre conjugue matériaux nobles et attentions raffinées."
          />
        </ScrollReveal>

        <div className="mt-16 grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
          {rooms.map((room, i) => (
            <ScrollReveal key={room.id} delay={i * 100}>
              <RoomCard room={room} />
            </ScrollReveal>
          ))}
        </div>

        <ScrollReveal className="mt-14 flex justify-center">
          <Link
            href="/rooms"
            className="group flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-gold transition-colors hover:text-gold-soft"
          >
            Voir toutes les chambres
            <ArrowRight className="size-4 transition-transform group-hover:translate-x-1" />
          </Link>
        </ScrollReveal>
      </div>
    </section>
  )
}
