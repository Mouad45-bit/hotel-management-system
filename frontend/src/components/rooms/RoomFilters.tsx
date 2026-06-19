import { RoomFilters as FilterTypes } from "@/services/room.service";
import { RoomStatus, RoomType } from "@/types/room";
import { Search } from "lucide-react";

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

const selectClass =
    "rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm text-zinc-700 transition focus:border-zinc-400 focus:outline-none focus:ring-2 focus:ring-zinc-100";

export function RoomFilters({ filters, onFilterChange, onReset, count }: RoomFiltersProps) {
    const hasFilters = Object.values(filters).some(Boolean);

    return (
        <div className="flex flex-col gap-3 rounded-2xl bg-white p-4 shadow-sm ring-1 ring-zinc-200 lg:flex-row lg:items-center">
            <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" />
                <input
                    type="text"
                    placeholder="Rechercher par numéro de chambre..."
                    value={filters.number ?? ""}
                    onChange={(e) => onFilterChange("number", e.target.value)}
                    className="w-full rounded-xl border border-zinc-200 bg-white py-2.5 pl-11 pr-4 text-sm text-zinc-700 placeholder:text-zinc-400 transition focus:border-zinc-400 focus:outline-none focus:ring-2 focus:ring-zinc-100"
                />
            </div>

            <select
                value={filters.type ?? ""}
                onChange={(e) => onFilterChange("type", e.target.value)}
                className={selectClass}
            >
                <option value="">Tous les types</option>
                {(Object.keys(TYPE_LABELS) as RoomType[]).map((t) => (
                    <option key={t} value={t}>{TYPE_LABELS[t]}</option>
                ))}
            </select>

            <select
                value={filters.status ?? ""}
                onChange={(e) => onFilterChange("status", e.target.value)}
                className={selectClass}
            >
                <option value="">Tous les statuts</option>
                {(Object.keys(STATUS_LABELS) as RoomStatus[]).map((s) => (
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
                {count} chambre{count > 1 ? "s" : ""}
            </span>
        </div>
    );
}
