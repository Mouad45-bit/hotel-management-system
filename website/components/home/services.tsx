import Image from 'next/image'
import { BellRing, Flower2, UtensilsCrossed, Waves } from 'lucide-react'
import { SectionHeading } from '@/components/section-heading'
import { ScrollReveal } from '@/components/scroll-reveal'

const SERVICES = [
  {
    icon: Flower2,
    title: 'Spa & Bien-être',
    description: 'Soins signature, sauna et hammam dans un havre de sérénité.',
  },
  {
    icon: UtensilsCrossed,
    title: 'Restaurant étoilé',
    description: 'Une cuisine gastronomique orchestrée par un chef de renom.',
  },
  {
    icon: Waves,
    title: 'Piscine intérieure',
    description: 'Une piscine chauffée baignée de lumière, ouverte à toute heure.',
  },
  {
    icon: BellRing,
    title: 'Conciergerie 24/7',
    description: 'Une équipe dévouée pour exaucer chacun de vos souhaits.',
  },
]

export function Services() {
  return (
    <section className="relative overflow-hidden bg-card py-24 lg:py-32">
      <div className="mx-auto grid max-w-7xl items-center gap-16 px-6 lg:grid-cols-2 lg:px-10">
        <ScrollReveal className="relative aspect-[4/5] overflow-hidden rounded-3xl">
          <Image
            src="/images/spa.png"
            alt="Spa et piscine de l'hôtel"
            fill
            sizes="(max-width: 1024px) 100vw, 50vw"
            className="object-cover"
          />
        </ScrollReveal>

        <div>
          <ScrollReveal>
            <SectionHeading
              align="left"
              eyebrow="Nos services"
              title="Une expérience d'exception"
              description="Tout est pensé pour transformer votre séjour en parenthèse hors du temps."
            />
          </ScrollReveal>

          <div className="mt-12 grid gap-6 sm:grid-cols-2">
            {SERVICES.map((service, i) => (
              <ScrollReveal key={service.title} delay={i * 100}>
                <div className="h-full rounded-2xl border border-border bg-background p-6 transition-colors hover:border-gold/60">
                  <span className="flex size-12 items-center justify-center rounded-full border border-gold/40 text-gold">
                    <service.icon className="size-5" />
                  </span>
                  <h3 className="mt-5 font-serif text-xl text-cream">{service.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                    {service.description}
                  </p>
                </div>
              </ScrollReveal>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
