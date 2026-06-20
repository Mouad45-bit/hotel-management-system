import { ClientFilters as FilterTypes } from '@/services/client.service';
import { Search } from 'lucide-react';

interface ClientFiltersProps {
    filters: FilterTypes;
    onFilterChange: (key: keyof FilterTypes, value: string) => void;
    onReset: () => void;
    count: number;
}

export function ClientFilters({ filters, onFilterChange, onReset, count }: ClientFiltersProps) {
    const hasFilters = Object.values(filters).some(Boolean);

    return (
        <div className="flex flex-col gap-3 rounded-2xl bg-white p-4 shadow-sm ring-1 ring-zinc-200 lg:flex-row lg:items-center">
            <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" />
                <input
                    type="text"
                    placeholder="Rechercher par nom, email, CIN ou téléphone..."
                    value={filters.search ?? ''}
                    onChange={(e) => onFilterChange('search', e.target.value)}
                    className="w-full rounded-xl border border-zinc-200 bg-white py-2.5 pl-11 pr-4 text-sm text-zinc-700 placeholder:text-zinc-400 transition focus:border-zinc-400 focus:outline-none focus:ring-2 focus:ring-zinc-100"
                />
            </div>

            {hasFilters && (
                <button
                    onClick={onReset}
                    className="text-sm font-medium text-zinc-500 underline transition hover:text-zinc-800"
                >
                    Réinitialiser
                </button>
            )}

            <span className="shrink-0 px-2 text-sm font-medium text-zinc-500 lg:ml-auto">
                {count} client{count > 1 ? 's' : ''}
            </span>
        </div>
    );
}
