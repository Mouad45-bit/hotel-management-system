"use client";

import { Search } from "lucide-react";
import type { ReservationFilters as FilterTypes } from "@/services/reservation.service";
import type { ReservationStatus } from "@/types/reservation";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
import { HmsButton } from "@/components/hms/HmsButton";

interface ReservationFiltersProps {
    filters: FilterTypes;
    onFilterChange: (key: keyof FilterTypes, value: string) => void;
    onReset: () => void;
    count: number;
}

const STATUS_LABELS: Record<ReservationStatus, string> = {
    CREATED: "Créée",
    CONFIRMED: "Confirmée",
    CHECKED_IN: "Check-in",
    CHECKED_OUT: "Check-out",
    CANCELLED: "Annulée",
    NO_SHOW: "No-show",
};

export function ReservationFilters({ filters, onFilterChange, onReset, count }: ReservationFiltersProps) {
    const hasFilters = Object.values(filters).some(Boolean);

    return (
        <div className="flex flex-col gap-3 lg:flex-row lg:items-end">
            <div className="relative flex-1">
                <Search
                    aria-hidden="true"
                    className="pointer-events-none absolute left-4 top-[42px] h-4 w-4 text-[var(--hms-text-muted)]"
                    strokeWidth={1.8}
                />
                <HmsInput
                    id="reservation-search"
                    label="Recherche"
                    type="text"
                    placeholder="Rechercher par ID chambre ou client..."
                    value={filters.roomId ?? ""}
                    onChange={(e) => onFilterChange("roomId", e.target.value)}
                    className="[&_input]:pl-10"
                />
            </div>

            <HmsSelect
                id="reservation-status-filter"
                label="Statut"
                value={filters.status ?? ""}
                onChange={(e) => onFilterChange("status", e.target.value)}
            >
                <option value="">Tous les statuts</option>
                {(Object.keys(STATUS_LABELS) as ReservationStatus[]).map((s) => (
                    <option key={s} value={s}>{STATUS_LABELS[s]}</option>
                ))}
            </HmsSelect>

            {hasFilters && (
                <HmsButton type="button" variant="secondary" onClick={onReset}>
                    Réinitialiser
                </HmsButton>
            )}

            <span className="shrink-0 px-2 text-sm font-medium text-[var(--hms-text-muted)] lg:ml-auto">
                {count} réservation{count > 1 ? "s" : ""}
            </span>
        </div>
    );
}
