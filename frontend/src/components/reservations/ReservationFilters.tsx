"use client";

import { Popover, PopoverButton, PopoverPanel } from "@headlessui/react";
import { ListFilter } from "lucide-react";
import type { ReservationFilters as FilterTypes } from "@/services/reservation.service";
import type { ReservationStatus } from "@/types/reservation";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
import { cn } from "@/lib/utils";

interface ReservationFiltersProps {
    filters: FilterTypes;
    onFilterChange: (key: keyof FilterTypes, value: string) => void;
}

const STATUS_LABELS: Record<ReservationStatus, string> = {
    CREATED: "Créée",
    CONFIRMED: "Confirmée",
    CHECKED_IN: "Check-in",
    CHECKED_OUT: "Check-out",
    CANCELLED: "Annulée",
    NO_SHOW: "No-show",
};

export function ReservationFilters({ filters, onFilterChange }: ReservationFiltersProps) {
    return (
        <Popover className="relative">
            {({ open }) => (
                <>
                    <PopoverButton
                        className={cn(
                            "inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2",
                            open
                                ? "bg-[var(--hms-primary-active)]"
                                : "bg-[var(--hms-primary)] hover:bg-[var(--hms-primary-hover)]"
                        )}
                    >
                        <ListFilter aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        Filtrer
                    </PopoverButton>

                    <PopoverPanel className="absolute right-0 top-full z-30 mt-3 w-[min(760px,calc(100vw-2.5rem))] rounded-[20px] border border-[var(--hms-soft-border)] bg-white p-5 shadow-[0_24px_70px_rgba(13,9,7,0.14)]">
                        <div className="grid gap-4 md:grid-cols-3">
                            <HmsInput
                                id="reservation-room-filter"
                                label="Chambre"
                                type="text"
                                inputMode="numeric"
                                placeholder="201"
                                value={filters.roomId ?? ""}
                                onChange={(event) => onFilterChange("roomId", event.target.value)}
                            />

                            <HmsInput
                                id="reservation-client-filter"
                                label="Client"
                                type="text"
                                inputMode="numeric"
                                placeholder="15"
                                value={filters.clientId ?? ""}
                                onChange={(event) => onFilterChange("clientId", event.target.value)}
                            />

                            <HmsSelect
                                id="reservation-status-filter"
                                label="Statut"
                                value={filters.status ?? ""}
                                onChange={(event) => onFilterChange("status", event.target.value)}
                            >
                                <option value="">Tous les statuts</option>
                                {(Object.keys(STATUS_LABELS) as ReservationStatus[]).map((status) => (
                                    <option key={status} value={status}>{STATUS_LABELS[status]}</option>
                                ))}
                            </HmsSelect>
                        </div>
                    </PopoverPanel>
                </>
            )}
        </Popover>
    );
}
