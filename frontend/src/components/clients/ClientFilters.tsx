import { Search } from "lucide-react";
import type { ClientFilters as FilterTypes } from "@/services/client.service";
import { HmsInput } from "@/components/hms/HmsField";
import { HmsButton } from "@/components/hms/HmsButton";

interface ClientFiltersProps {
    filters: FilterTypes;
    onFilterChange: (key: keyof FilterTypes, value: string) => void;
    onReset: () => void;
    count: number;
}

export function ClientFilters({ filters, onFilterChange, onReset, count }: ClientFiltersProps) {
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
                    id="client-search"
                    label="Recherche"
                    type="text"
                    placeholder="Rechercher par nom, email, CIN ou téléphone..."
                    value={filters.search ?? ""}
                    onChange={(e) => onFilterChange("search", e.target.value)}
                    className="[&_input]:pl-10"
                />
            </div>

            {hasFilters && (
                <HmsButton type="button" variant="secondary" onClick={onReset}>
                    Réinitialiser
                </HmsButton>
            )}

            <span className="shrink-0 px-2 text-sm font-medium text-[var(--hms-text-muted)] lg:ml-auto">
                {count} client{count > 1 ? "s" : ""}
            </span>
        </div>
    );
}
