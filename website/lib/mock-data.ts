import type { Room } from './types'

export const ROOMS: Room[] = [
  {
    id: 'r-101',
    number: '101',
    type: 'Simple',
    floor: 1,
    capacity: 1,
    pricePerNight: 180,
    image: '/images/room-simple.png',
    description:
      'Un cocon raffiné pour le voyageur solitaire, alliant confort et sobriété élégante.',
    amenities: ['Lit simple premium', 'Wi-Fi fibre', 'Petit-déjeuner inclus', 'Vue jardin'],
  },
  {
    id: 'r-205',
    number: '205',
    type: 'Double',
    floor: 2,
    capacity: 2,
    pricePerNight: 290,
    image: '/images/room-double.png',
    description:
      'Spacieuse et lumineuse, idéale pour un séjour à deux dans un écrin de douceur.',
    amenities: ['Lit king-size', 'Wi-Fi fibre', 'Minibar', 'Vue ville'],
  },
  {
    id: 'r-210',
    number: '210',
    type: 'Double',
    floor: 2,
    capacity: 2,
    pricePerNight: 310,
    image: '/images/room-double.png',
    description:
      'Une chambre double aux finitions soignées, baignée de lumière naturelle.',
    amenities: ['Lit king-size', 'Wi-Fi fibre', 'Minibar', 'Balcon privé'],
  },
  {
    id: 'r-305',
    number: '305',
    type: 'Suite',
    floor: 3,
    capacity: 3,
    pricePerNight: 540,
    image: '/images/room-suite.png',
    description:
      'Un salon séparé, des matériaux nobles et une vue imprenable pour un séjour mémorable.',
    amenities: ['Salon privé', 'Lit king-size', 'Baignoire îlot', 'Service majordome'],
  },
  {
    id: 'r-410',
    number: '410',
    type: 'Deluxe',
    floor: 4,
    capacity: 4,
    pricePerNight: 820,
    image: '/images/room-deluxe.png',
    description:
      "L'expérience ultime : penthouse panoramique, lustre et marbre, le sommet du raffinement.",
    amenities: ['Vue panoramique', 'Terrasse privée', 'Lustre', 'Service VIP 24/7'],
  },
  {
    id: 'r-411',
    number: '411',
    type: 'Suite',
    floor: 4,
    capacity: 3,
    pricePerNight: 580,
    image: '/images/room-suite.png',
    description:
      'Suite d’angle baignée de lumière, avec coin lounge et dressing privatif.',
    amenities: ['Salon privé', 'Dressing', 'Baignoire îlot', 'Service majordome'],
  },
]
