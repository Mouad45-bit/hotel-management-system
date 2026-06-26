'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useEffect, useState } from 'react'
import { Menu, X } from 'lucide-react'

const LINKS = [
  { href: '/', label: 'Accueil' },
  { href: '/rooms', label: 'Chambres' },
  { href: '/my-booking', label: 'Ma réservation' },
]

export function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const [open, setOpen] = useState(false)
  const pathname = usePathname()

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    setOpen(false)
  }, [pathname])

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 transition-all duration-500 ${
        scrolled || open
          ? 'bg-background/90 backdrop-blur-md border-b border-border'
          : 'bg-transparent border-b border-transparent'
      }`}
    >
      <nav className="mx-auto flex max-w-7xl items-center justify-between px-6 py-5 lg:px-10">
        <Link href="/" className="flex items-center gap-3" aria-label="Maison Lumière, accueil">
          <span className="flex size-9 items-center justify-center rounded-full border border-gold text-gold font-serif text-lg">
            M
          </span>
          <span className="flex flex-col leading-none">
            <span className="font-serif text-lg tracking-wide text-cream">Maison Lumière</span>
            <span className="text-[10px] uppercase tracking-[0.3em] text-gold">Hôtel 5 étoiles</span>
          </span>
        </Link>

        <div className="hidden items-center gap-10 md:flex">
          {LINKS.map((link) => {
            const active = pathname === link.href
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`text-sm tracking-wide transition-colors hover:text-gold ${
                  active ? 'text-gold' : 'text-cream/80'
                }`}
              >
                {link.label}
              </Link>
            )
          })}
          <Link
            href="/rooms"
            className="rounded-full bg-gold px-6 py-2.5 text-sm font-medium tracking-wide text-ink transition-colors hover:bg-gold-soft"
          >
            Réserver
          </Link>
        </div>

        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="text-cream md:hidden"
          aria-label={open ? 'Fermer le menu' : 'Ouvrir le menu'}
        >
          {open ? <X className="size-6" /> : <Menu className="size-6" />}
        </button>
      </nav>

      {open && (
        <div className="border-t border-border bg-background/95 px-6 py-6 md:hidden">
          <div className="flex flex-col gap-5">
            {LINKS.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="text-base text-cream/90 transition-colors hover:text-gold"
              >
                {link.label}
              </Link>
            ))}
            <Link
              href="/rooms"
              className="mt-2 rounded-full bg-gold px-6 py-3 text-center text-sm font-medium text-ink"
            >
              Réserver
            </Link>
          </div>
        </div>
      )}
    </header>
  )
}
