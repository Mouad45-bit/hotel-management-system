'use client';

import { ReservationStatus } from '@/types/reservation';
import { cn } from '@/lib/utils';

const STATUS_CONFIG: Record<ReservationStatus, { label: string; bg: string; text: string; ring: string }> = {
    CREATED: { label: 'Créée', bg: 'bg-blue-50', text: 'text-blue-700', ring: 'ring-blue-200' },
    CONFIRMED: { label: 'Confirmée', bg: 'bg-indigo-50', text: 'text-indigo-700', ring: 'ring-indigo-200' },
    CHECKED_IN: { label: 'Check-in', bg: 'bg-emerald-50', text: 'text-emerald-700', ring: 'ring-emerald-200' },
    CHECKED_OUT: { label: 'Check-out', bg: 'bg-zinc-100', text: 'text-zinc-600', ring: 'ring-zinc-200' },
    CANCELLED: { label: 'Annulée', bg: 'bg-red-50', text: 'text-red-700', ring: 'ring-red-200' },
    NO_SHOW: { label: 'No-show', bg: 'bg-orange-50', text: 'text-orange-700', ring: 'ring-orange-200' },
};

export function ReservationStatusBadge({ status }: { status: ReservationStatus }) {
    const config = STATUS_CONFIG[status] ?? STATUS_CONFIG.CREATED;
    return (
        <span
            className={cn(
                'inline-flex items-center rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset',
                config.bg, config.text, config.ring
            )}
        >
            {config.label}
        </span>
    );
}
