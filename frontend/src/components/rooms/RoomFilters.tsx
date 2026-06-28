"use client";

import { Popover, PopoverButton, PopoverPanel } from "@headlessui/react";
import { ListFilter, Search } from "lucide-react";
import type { RoomFilters as FilterTypes } from "@/services/room.service";
import type { RoomStatus, RoomType } from "@/types/room";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
import { cn } from "@/lib/utils";

interface RoomFiltersProps {
    filters: FilterTypes;
    onFilterChange: (key: keyof FilterTypes, value: string) => void;
}

const STATUS_LABELS: Record<RoomStatus, string> = {
    AVAILABLE: "Disponible", OCCUPIED: "Occupée", RESERVED: "Réservée",
    CLEANING: "Nettoyage", MAINTENANCE: "Maintenance", OUT_OF_SERVICE: "Hors service",
};

const TYPE_LABELS: Record<RoomType, string> = {
    SINGLE: "Single", DOUBLE: "Double", TWIN: "Twin",
    SUITE: "Suite", FAMILY: "Family", DELUXE: "Deluxe",
};

export function RoomFilters({ filters, onFilterChange }: RoomFiltersProps) {
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
                            <div className="relative">
                                <Search
                                    aria-hidden="true"
                                    className="pointer-events-none absolute bottom-4 left-4 h-4 w-4 text-[var(--hms-text-muted)]"
                                    strokeWidth={1.8}
                                />

                                <HmsInput
                                    id="room-search"
                                    label="Numéro"
                                    type="text"
                                    placeholder="101"
                                    value={filters.number ?? ""}
                                    onChange={(event) => onFilterChange("number", event.target.value)}
                                    className="[&_input]:pl-10"
                                />
                            </div>

                            <HmsSelect
                                id="room-type-filter"
                                label="Type"
                                value={filters.type ?? ""}
                                onChange={(event) => onFilterChange("type", event.target.value)}
                            >
                                <option value="">Tous les types</option>
                                {(Object.keys(TYPE_LABELS) as RoomType[]).map((type) => (
                                    <option key={type} value={type}>{TYPE_LABELS[type]}</option>
                                ))}
                            </HmsSelect>

                            <HmsSelect
                                id="room-status-filter"
                                label="Statut"
                                value={filters.status ?? ""}
                                onChange={(event) => onFilterChange("status", event.target.value)}
                            >
                                <option value="">Tous les statuts</option>
                                {(Object.keys(STATUS_LABELS) as RoomStatus[]).map((status) => (
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
