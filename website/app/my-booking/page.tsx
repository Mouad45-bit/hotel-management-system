import { Navbar } from '@/components/navbar'
import { Footer } from '@/components/footer'
import { PageBanner } from '@/components/page-banner'
import { MyBookingView } from '@/components/booking/my-booking-view'

export const metadata = {
  title: 'Ma réservation — Maison Lumière',
}

export default function MyBookingPage() {
  return (
    <>
      <Navbar />
      <main>
        <PageBanner
          eyebrow="Espace client"
          title="Consulter ma réservation"
          description="Saisissez votre référence et votre email pour retrouver tous les détails de votre séjour."
        />
        <MyBookingView />
      </main>
      <Footer />
    </>
  )
}
