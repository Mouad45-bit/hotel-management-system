import Link from 'next/link'
import { ArrowLeft } from 'lucide-react'
import { Navbar } from '@/components/navbar'
import { Footer } from '@/components/footer'

export const metadata = {
  title: 'Page introuvable — Maison Lumière',
}

export default function NotFound() {
  return (
    <>
      <Navbar />
      <main className="flex min-h-[70vh] items-center justify-center px-6 pt-24">
        <div className="mx-auto max-w-lg text-center">
          <p className="font-serif text-8xl text-gold">404</p>
          <h1 className="mt-6 text-balance font-serif text-3xl text-cream sm:text-4xl">
            Page introuvable
          </h1>
          <p className="mt-4 leading-relaxed text-muted-foreground">
            La page que vous recherchez n&apos;existe pas ou a été déplacée.
          </p>
          <Link
            href="/"
            className="mt-8 inline-flex items-center gap-2 rounded-full bg-gold px-7 py-3.5 text-sm font-medium text-ink transition-colors hover:bg-gold-soft"
          >
            <ArrowLeft className="size-4" />
            Retour à l&apos;accueil
          </Link>
        </div>
      </main>
      <Footer />
    </>
  )
}
