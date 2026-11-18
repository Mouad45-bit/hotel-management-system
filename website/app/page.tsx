import { Navbar } from '@/components/navbar'
import { Footer } from '@/components/footer'
import { Hero } from '@/components/home/hero'
import { FeaturedRooms } from '@/components/home/featured-rooms'
import { Services } from '@/components/home/services'
import { Testimonials } from '@/components/home/testimonials'

export default function HomePage() {
  return (
    <>
      <Navbar />
      <main>
        <Hero />
        <FeaturedRooms />
        <Services />
        <Testimonials />
      </main>
      <Footer />
    </>
  )
}
