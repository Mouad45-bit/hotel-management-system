import Link from 'next/link'
import { Camera, Globe, Mail, MapPin, Phone, Send } from 'lucide-react'

export function Footer() {
  return (
    <footer className="border-t border-border bg-background">
      <div className="mx-auto max-w-7xl px-6 py-16 lg:px-10">
        <div className="grid gap-12 md:grid-cols-2 lg:grid-cols-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="flex size-9 items-center justify-center rounded-full border border-gold font-serif text-lg text-gold">
                M
              </span>
              <span className="font-serif text-xl text-cream">Maison Lumière</span>
            </div>
            <p className="mt-5 max-w-xs text-sm leading-relaxed text-muted-foreground">
              L&apos;art de recevoir depuis 1924. Un sanctuaire de raffinement au cœur de la ville,
              où chaque détail célèbre l&apos;élégance.
            </p>
            <div className="mt-6 flex items-center gap-4">
              {[Camera, Globe, Send].map((Icon, i) => (
                <a
                  key={i}
                  href="#"
                  className="flex size-9 items-center justify-center rounded-full border border-border text-muted-foreground transition-colors hover:border-gold hover:text-gold"
                  aria-label="Réseau social"
                >
                  <Icon className="size-4" />
                </a>
              ))}
            </div>
          </div>

          <div>
            <h3 className="font-serif text-lg text-cream">Navigation</h3>
            <ul className="mt-5 space-y-3 text-sm text-muted-foreground">
              <li><Link href="/" className="transition-colors hover:text-gold">Accueil</Link></li>
              <li><Link href="/rooms" className="transition-colors hover:text-gold">Nos chambres</Link></li>
              <li><Link href="/my-booking" className="transition-colors hover:text-gold">Ma réservation</Link></li>
            </ul>
          </div>

          <div>
            <h3 className="font-serif text-lg text-cream">Services</h3>
            <ul className="mt-5 space-y-3 text-sm text-muted-foreground">
              <li>Spa &amp; Bien-être</li>
              <li>Restaurant étoilé</li>
              <li>Piscine intérieure</li>
              <li>Conciergerie 24/7</li>
            </ul>
          </div>

          <div>
            <h3 className="font-serif text-lg text-cream">Contact</h3>
            <ul className="mt-5 space-y-4 text-sm text-muted-foreground">
              <li className="flex items-start gap-3">
                <MapPin className="mt-0.5 size-4 shrink-0 text-gold" />
                <span>12 Avenue des Lumières, 75008 Paris, France</span>
              </li>
              <li className="flex items-center gap-3">
                <Phone className="size-4 shrink-0 text-gold" />
                <span>+33 1 42 00 00 00</span>
              </li>
              <li className="flex items-center gap-3">
                <Mail className="size-4 shrink-0 text-gold" />
                <span>contact@maison-lumiere.fr</span>
              </li>
            </ul>
          </div>
        </div>

        <div className="mt-14 flex flex-col items-center justify-between gap-4 border-t border-border pt-8 text-xs text-muted-foreground md:flex-row">
          <p>© {new Date().getFullYear()} Maison Lumière. Tous droits réservés.</p>
          <p className="tracking-wide">Hotel Management System</p>
        </div>
      </div>
    </footer>
  )
}
