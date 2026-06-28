import { Search } from "lucide-react";
import type { RoomFilters as FilterTypes } from "@/services/room.service";
import type { RoomStatus, RoomType } from "@/types/room";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
import { HmsButton } from "@/components/hms/HmsButton";

interface RoomFiltersProps {
    filters: FilterTypes;
    onFilterChange: (key: keyof FilterTypes, value: string) => void;
    onReset: () => void;
    count: number;
}

const STATUS_LABELS: Record<RoomStatus, string> = {
    AVAILABLE: "Disponible", OCCUPIED: "Occupée", RESERVED: "Réservée",
    CLEANING: "Nettoyage", MAINTENANCE: "Maintenance", OUT_OF_SERVICE: "Hors service",
};

const TYPE_LABELS: Record<RoomType, string> = {
    SINGLE: "Single", DOUBLE: "Double", TWIN: "Twin",
    SUITE: "Suite", FAMILY: "Family", DELUXE: "Deluxe",
};

export function RoomFilters({ filters, onFilterChange, onReset, count }: RoomFiltersProps) {
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
                    id="room-search"
                    label="Recherche"
                    type="text"
                    placeholder="Rechercher par numéro de chambre..."
                    value={filters.number ?? ""}
                    onChange={(e) => onFilterChange("number", e.target.value)}
                    className="[&_input]:pl-10"
                />
            </div>

            <HmsSelect
                id="room-type-filter"
                label="Type"
                value={filters.type ?? ""}
                onChange={(e) => onFilterChange("type", e.target.value)}
            >
                <option value="">Tous les types</option>
                {(Object.keys(TYPE_LABELS) as RoomType[]).map((t) => (
                    <option key={t} value={t}>{TYPE_LABELS[t]}</option>
                ))}
            </HmsSelect>

            <HmsSelect
                id="room-status-filter"
                label="Statut"
                value={filters.status ?? ""}
                onChange={(e) => onFilterChange("status", e.target.value)}
            >
                <option value="">Tous les statuts</option>
                {(Object.keys(STATUS_LABELS) as RoomStatus[]).map((s) => (
                    <option key={s} value={s}>{STATUS_LABELS[s]}</option>
                ))}
            </HmsSelect>

            {hasFilters && (
                <HmsButton type="button" variant="secondary" onClick={onReset}>
                    Réinitialiser
                </HmsButton>
            )}

            <span className="shrink-0 px-2 text-sm font-medium text-[var(--hms-text-muted)] lg:ml-auto">
                {count} chambre{count > 1 ? "s" : ""}
            </span>
        </div>
    );
}
