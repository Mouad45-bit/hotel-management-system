'use client';

import { ReservationFilters as FilterTypes } from '@/services/reservation.service';
import { ReservationStatus } from '@/types/reservation';
import { Search } from 'lucide-react';

interface ReservationFiltersProps {
    filters: FilterTypes;
    onFilterChange: (key: keyof FilterTypes, value: string) => void;
    onReset: () => void;
    count: number;
}

const STATUS_LABELS: Record<ReservationStatus, string> = {
    CREATED: 'Créée',
    CONFIRMED: 'Confirmée',
    CHECKED_IN: 'Check-in',
    CHECKED_OUT: 'Check-out',
    CANCELLED: 'Annulée',
    NO_SHOW: 'No-show',
};

const selectClass =
    'rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm text-zinc-700 transition focus:border-zinc-400 focus:outline-none focus:ring-2 focus:ring-zinc-100';

export function ReservationFilters({ filters, onFilterChange, onReset, count }: ReservationFiltersProps) {
    const hasFilters = Object.values(filters).some(Boolean);

    return (
        <div className="flex flex-col gap-3 rounded-2xl bg-white p-4 shadow-sm ring-1 ring-zinc-200 lg:flex-row lg:items-center">
            <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" />
                <input
                    type="text"
                    placeholder="Rechercher par ID chambre ou client..."
                    value={filters.roomId ?? ''}
                    onChange={(e) => onFilterChange('roomId', e.target.value)}
                    className="w-full rounded-xl border border-zinc-200 bg-white py-2.5 pl-11 pr-4 text-sm text-zinc-700 placeholder:text-zinc-400 transition focus:border-zinc-400 focus:outline-none focus:ring-2 focus:ring-zinc-100"
                />
            </div>

            <select
                value={filters.status ?? ''}
                onChange={(e) => onFilterChange('status', e.target.value)}
                className={selectClass}
            >
                <option value="">Tous les statuts</option>
                {(Object.keys(STATUS_LABELS) as ReservationStatus[]).map((s) => (
                    <option key={s} value={s}>{STATUS_LABELS[s]}</option>
                ))}
            </select>

            {hasFilters && (
                <button
                    onClick={onReset}
                    className="text-sm font-medium text-zinc-500 underline transition hover:text-zinc-800"
                >
                    Réinitialiser
                </button>
            )}

            <span className="shrink-0 px-2 text-sm font-medium text-zinc-500 lg:ml-auto">
                {count} réservation{count > 1 ? 's' : ''}
            </span>
        </div>
    );
}
