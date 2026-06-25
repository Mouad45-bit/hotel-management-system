"use client";

import { Popover, PopoverButton, PopoverPanel } from "@headlessui/react";
import { Check, ListFilter, RotateCcw, Search } from "lucide-react";
import { useState } from "react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
import { cn } from "@/lib/utils";
import {
    ACTIVE_STATUS_FILTER_LABELS,
    DEPARTMENT_FILTER_LABELS,
    DEFAULT_STAFF_FILTERS,
    DEPARTMENTS,
    type ActiveStatusFilter,
    type DepartmentFilter,
    type StaffFiltersState,
} from "@/types/staff";

interface StaffFiltersProps {
    filters: StaffFiltersState;
    errors?: Partial<Record<keyof StaffFiltersState, string>>;
    onApply: (filters: StaffFiltersState) => void;
    onReset: () => void;
}

const DEPARTMENT_OPTIONS: DepartmentFilter[] = ["ALL", ...DEPARTMENTS];
const ACTIVE_OPTIONS: ActiveStatusFilter[] = ["ALL", "ACTIVE", "INACTIVE"];

export function StaffFilters({
    filters,
    errors = {},
    onApply,
    onReset,
}: StaffFiltersProps) {
    const [draftFilters, setDraftFilters] = useState<StaffFiltersState>(filters);

    function updateField<K extends keyof StaffFiltersState>(
        field: K,
        value: StaffFiltersState[K]
    ) {
        setDraftFilters((current) => ({ ...current, [field]: value }));
    }

    function handleReset() {
        setDraftFilters(DEFAULT_STAFF_FILTERS);
        onReset();
    }

    return (
        <Popover className="relative">
            {({ open, close }) => (
                <>
                    <PopoverButton
                        className={cn(
                            "inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2",
                            open ? "bg-[var(--hms-primary-active)]" : "bg-[var(--hms-primary)] hover:bg-[var(--hms-primary-hover)]"
                        )}
                    >
                        <ListFilter aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        Filtrer
                    </PopoverButton>

                    <PopoverPanel className="absolute right-0 top-full z-30 mt-3 w-[min(760px,calc(100vw-2.5rem))] rounded-[20px] border border-[var(--hms-soft-border)] bg-white p-5 shadow-[0_24px_70px_rgba(13,9,7,0.14)]">
                        <div className="space-y-5">
                            <div>
                                <h3 className="text-sm font-bold text-[var(--hms-text)]">Filtres</h3>
                                <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                    Recherchez par nom, email, téléphone ou CIN.
                                </p>
                            </div>

                            <div className="grid gap-4 md:grid-cols-3">
                                <div className="relative">
                                    <Search
                                        aria-hidden="true"
                                        className="pointer-events-none absolute left-4 top-[42px] h-4 w-4 text-[var(--hms-text-muted)]"
                                        strokeWidth={1.8}
                                    />
                                    <HmsInput
                                        id="staff-keyword-filter"
                                        label="Recherche"
                                        value={draftFilters.keyword}
                                        onChange={(event) => updateField("keyword", event.target.value)}
                                        placeholder="Nom, email, CIN..."
                                        error={errors.keyword}
                                        className="[&_input]:pl-10"
                                    />
                                </div>

                                <HmsSelect
                                    id="staff-department-filter"
                                    label="Département"
                                    value={draftFilters.department}
                                    onChange={(event) => updateField("department", event.target.value as DepartmentFilter)}
                                    error={errors.department}
                                >
                                    {DEPARTMENT_OPTIONS.map((department) => (
                                        <option key={department} value={department}>
                                            {DEPARTMENT_FILTER_LABELS[department]}
                                        </option>
                                    ))}
                                </HmsSelect>

                                <HmsSelect
                                    id="staff-active-filter"
                                    label="Statut"
                                    value={draftFilters.active}
                                    onChange={(event) => updateField("active", event.target.value as ActiveStatusFilter)}
                                    error={errors.active}
                                >
                                    {ACTIVE_OPTIONS.map((active) => (
                                        <option key={active} value={active}>
                                            {ACTIVE_STATUS_FILTER_LABELS[active]}
                                        </option>
                                    ))}
                                </HmsSelect>
                            </div>

                            <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
                                <HmsButton type="button" variant="secondary" onClick={handleReset}>
                                    <RotateCcw aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                    Réinitialiser
                                </HmsButton>
                                <HmsButton
                                    type="button"
                                    onClick={() => {
                                        onApply(draftFilters);
                                        close();
                                    }}
                                >
                                    <Check aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                    Appliquer les filtres
                                </HmsButton>
                            </div>
                        </div>
                    </PopoverPanel>
                </>
            )}
        </Popover>
    );
}
