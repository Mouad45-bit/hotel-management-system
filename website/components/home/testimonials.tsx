import { Quote, Star } from 'lucide-react'
import { SectionHeading } from '@/components/section-heading'
import { ScrollReveal } from '@/components/scroll-reveal'

const TESTIMONIALS = [
  {
    name: 'Élodie Marchand',
    role: 'Séjour en Suite',
    quote:
      'Un séjour absolument féerique. Le service était impeccable et la chambre, un véritable joyau. Nous reviendrons sans hésiter.',
  },
  {
    name: 'James Whitmore',
    role: 'Voyage d\'affaires',
    quote:
      'Le raffinement à l\'état pur. La conciergerie a anticipé le moindre de mes besoins. Une adresse d\'exception.',
  },
  {
    name: 'Sofia Bianchi',
    role: 'Week-end romantique',
    quote:
      'Le spa, le restaurant, la vue… tout était sublime. Maison Lumière mérite amplement ses cinq étoiles.',
  },
]

export function Testimonials() {
  return (
    <section className="bg-background py-24 lg:py-32">
      <div className="mx-auto max-w-7xl px-6 lg:px-10">
        <ScrollReveal>
          <SectionHeading
            eyebrow="Avis clients"
            title="Ils ont vécu l'expérience"
            description="La plus belle des récompenses : la confiance et l'émotion de nos hôtes."
          />
        </ScrollReveal>

        <div className="mt-16 grid gap-8 md:grid-cols-3">
          {TESTIMONIALS.map((t, i) => (
            <ScrollReveal key={t.name} delay={i * 120}>
              <figure className="flex h-full flex-col rounded-2xl border border-border bg-card p-8">
                <Quote className="size-8 text-gold/40" />
                <div className="mt-4 flex items-center gap-1 text-gold">
                  {Array.from({ length: 5 }).map((_, s) => (
                    <Star key={s} className="size-4 fill-gold" />
                  ))}
                </div>
                <blockquote className="mt-5 flex-1 text-pretty leading-relaxed text-cream/90">
                  “{t.quote}”
                </blockquote>
                <figcaption className="mt-6 border-t border-border pt-5">
                  <p className="font-serif text-lg text-cream">{t.name}</p>
                  <p className="text-sm text-muted-foreground">{t.role}</p>
                </figcaption>
              </figure>
            </ScrollReveal>
          ))}
        </div>
      </div>
    </section>
  )
}
