import Image from 'next/image'
import Link from 'next/link'
import { ArrowRight, Star } from 'lucide-react'

export function Hero() {
  return (
    <section className="relative flex min-h-screen items-center justify-center overflow-hidden">
      <Image
        src="/images/hero.png"
        alt="Façade de l'hôtel Maison Lumière au crépuscule"
        fill
        priority
        sizes="100vw"
        className="object-cover"
      />
      <div className="absolute inset-0 bg-gradient-to-b from-ink/80 via-ink/50 to-ink" />

      <div className="relative z-10 mx-auto max-w-4xl px-6 text-center">
        <div className="flex items-center justify-center gap-1 text-gold">
          {Array.from({ length: 5 }).map((_, i) => (
            <Star key={i} className="size-4 fill-gold" />
          ))}
        </div>
        <span className="mt-6 inline-block text-xs uppercase tracking-[0.4em] text-gold-soft">
          Hôtel 5 étoiles · Paris
        </span>
        <h1 className="mt-6 text-balance font-serif text-5xl leading-[1.05] text-cream sm:text-6xl lg:text-7xl">
          L&apos;art de recevoir, l&apos;élégance d&apos;un séjour inoubliable
        </h1>
        <p className="mx-auto mt-7 max-w-xl text-pretty text-lg leading-relaxed text-cream/80">
          Au cœur de la ville, Maison Lumière vous accueille dans un écrin de
          raffinement où chaque instant devient un souvenir précieux.
        </p>
        <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row">
          <Link
            href="/rooms"
            className="group flex items-center gap-2 rounded-full bg-gold px-8 py-4 text-sm font-medium tracking-wide text-ink transition-colors hover:bg-gold-soft"
          >
            Réserver maintenant
            <ArrowRight className="size-4 transition-transform group-hover:translate-x-1" />
          </Link>
          <Link
            href="#chambres"
            className="rounded-full border border-cream/30 px-8 py-4 text-sm font-medium tracking-wide text-cream transition-colors hover:border-gold hover:text-gold"
          >
            Découvrir nos chambres
          </Link>
        </div>
      </div>

      <div className="absolute bottom-10 left-1/2 z-10 -translate-x-1/2">
        <div className="flex h-12 w-7 items-start justify-center rounded-full border border-cream/30 p-2">
          <span className="h-2 w-1 animate-bounce rounded-full bg-gold" />
        </div>
      </div>
    </section>
  )
}
