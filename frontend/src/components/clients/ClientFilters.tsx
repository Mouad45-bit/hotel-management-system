"use client";

import { Popover, PopoverButton, PopoverPanel } from "@headlessui/react";
import { ListFilter, Search } from "lucide-react";
import type { ClientFilters as FilterTypes } from "@/services/client.service";
import { HmsInput } from "@/components/hms/HmsField";
import { cn } from "@/lib/utils";

interface ClientFiltersProps {
    filters: FilterTypes;
    onFilterChange: (key: keyof FilterTypes, value: string) => void;
}

export function ClientFilters({ filters, onFilterChange }: ClientFiltersProps) {
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

                    <PopoverPanel className="absolute right-0 top-full z-30 mt-3 w-[min(420px,calc(100vw-2.5rem))] rounded-[20px] border border-[var(--hms-soft-border)] bg-white p-5 shadow-[0_24px_70px_rgba(13,9,7,0.14)]">
                        <div className="relative">
                            <Search
                                aria-hidden="true"
                                className="pointer-events-none absolute bottom-4 left-4 h-4 w-4 text-[var(--hms-text-muted)]"
                                strokeWidth={1.8}
                            />
                            <HmsInput
                                id="client-search"
                                label="Recherche"
                                type="text"
                                placeholder="Nom, email, CIN ou téléphone"
                                value={filters.search ?? ""}
                                onChange={(event) => onFilterChange("search", event.target.value)}
                                className="[&_input]:pl-10"
                            />
                        </div>
                    </PopoverPanel>
                </>
            )}
        </Popover>
    );
}
