import {
    ROOM_TYPES,
    ROOM_STATUSES,
    ROOM_TYPE_LABELS,
    ROOM_STATUS_LABELS,
    RoomFiltersState,
    DEFAULT_ROOM_FILTERS,
} from "@/types/room";

interface RoomFiltersProps {
    filters: RoomFiltersState;
    onChange: (filters: RoomFiltersState) => void;
}

export function RoomFilters({ filters, onChange }: RoomFiltersProps) {

    const handleChange = (field: keyof RoomFiltersState, value: string) => {
        onChange({ ...filters, [field]: value });
    };

    const handleReset = () => {
        onChange(DEFAULT_ROOM_FILTERS);
    };

    const hasActiveFilters = Object.values(filters).some(v => v !== "");

    return (
        <div className="rounded-xl border border-zinc-200 bg-white p-4 shadow-sm">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
                {/* Numéro */}
                <input
                    type="text"
                    placeholder="Numéro..."
                    value={filters.number}
                    onChange={e => handleChange("number", e.target.value)}
                    className="rounded-md border border-zinc-300 px-3 py-2 text-sm text-zinc-900 focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                />

                {/* Type */}
                <select
                    value={filters.type}
                    onChange={e => handleChange("type", e.target.value)}
                    className="rounded-md border border-zinc-300 px-3 py-2 text-sm text-zinc-900 focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                >
                    <option value="">Tous les types</option>
                    {ROOM_TYPES.map(t => (
                        <option key={t} value={t}>{ROOM_TYPE_LABELS[t]}</option>
                    ))}
                </select>

                {/* Statut */}
                <select
                    value={filters.status}
                    onChange={e => handleChange("status", e.target.value)}
                    className="rounded-md border border-zinc-300 px-3 py-2 text-sm text-zinc-900 focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                >
                    <option value="">Tous les statuts</option>
                    {ROOM_STATUSES.map(s => (
                        <option key={s} value={s}>{ROOM_STATUS_LABELS[s]}</option>
                    ))}
                </select>

                {/* Étage */}
                <input
                    type="number"
                    placeholder="Étage..."
                    value={filters.floor}
                    onChange={e => handleChange("floor", e.target.value)}
                    className="rounded-md border border-zinc-300 px-3 py-2 text-sm text-zinc-900 focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                />

                {/* Capacité */}
                <input
                    type="number"
                    placeholder="Capacité..."
                    value={filters.capacity}
                    onChange={e => handleChange("capacity", e.target.value)}
                    className="rounded-md border border-zinc-300 px-3 py-2 text-sm text-zinc-900 focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                />
            </div>

            {/* Bouton réinitialiser — visible seulement si un filtre est actif */}
            {hasActiveFilters && (
                <div className="mt-3 flex justify-end">
                    <button
                        type="button"
                        onClick={handleReset}
                        className="text-sm font-medium text-stone-600 hover:text-stone-900"
                    >
                        Réinitialiser les filtres
                    </button>
                </div>
            )}
        </div>
    );
}
