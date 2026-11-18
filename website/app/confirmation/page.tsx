import { Suspense } from 'react'
import { Loader2 } from 'lucide-react'
import { Navbar } from '@/components/navbar'
import { Footer } from '@/components/footer'
import { ConfirmationView } from '@/components/booking/confirmation-view'

export const metadata = {
  title: 'Confirmation — Maison Lumière',
}

export default function ConfirmationPage() {
  return (
    <>
      <Navbar />
      <main className="pt-24">
        <Suspense
          fallback={
            <div className="flex items-center justify-center py-32 text-muted-foreground">
              <Loader2 className="size-6 animate-spin text-gold" />
            </div>
          }
        >
          <ConfirmationView />
        </Suspense>
      </main>
      <Footer />
    </>
  )
}
