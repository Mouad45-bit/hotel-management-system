'use client'

import { RefreshCcw } from 'lucide-react'

export default function ErrorPage({
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <main className="flex min-h-screen items-center justify-center px-6">
      <div className="mx-auto max-w-lg text-center">
        <p className="font-serif text-6xl text-gold">Oops</p>
        <h1 className="mt-6 text-balance font-serif text-3xl text-cream sm:text-4xl">
          Une erreur est survenue
        </h1>
        <p className="mt-4 leading-relaxed text-muted-foreground">
          Quelque chose ne s&apos;est pas passé comme prévu. Veuillez réessayer.
        </p>
        <button
          onClick={reset}
          className="mt-8 inline-flex items-center gap-2 rounded-full bg-gold px-7 py-3.5 text-sm font-medium text-ink transition-colors hover:bg-gold-soft"
        >
          <RefreshCcw className="size-4" />
          Réessayer
        </button>
      </div>
    </main>
  )
}
