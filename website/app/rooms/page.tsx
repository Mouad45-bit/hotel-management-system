import { Navbar } from '@/components/navbar'
import { Footer } from '@/components/footer'
import { PageBanner } from '@/components/page-banner'
import { RoomsBrowser } from '@/components/rooms/rooms-browser'
import { getRooms } from '@/lib/api'

export const metadata = {
  title: 'Nos chambres — Maison Lumière',
  description: 'Découvrez et réservez nos chambres et suites 5 étoiles disponibles.',
}

export default async function RoomsPage() {
  const rooms = await getRooms()

  return (
    <>
      <Navbar />
      <main>
        <PageBanner
          eyebrow="Disponibilités"
          title="Nos chambres & suites"
          description="Choisissez vos dates et le type de chambre qui vous ressemble. Le luxe n'attend que vous."
        />
        <RoomsBrowser rooms={rooms} />
      </main>
      <Footer />
    </>
  )
}
