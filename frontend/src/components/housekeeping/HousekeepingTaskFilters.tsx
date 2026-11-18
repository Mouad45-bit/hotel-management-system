"use client";

import { Popover, PopoverButton, PopoverPanel } from "@headlessui/react";
import { ListFilter } from "lucide-react";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
import { cn } from "@/lib/utils";
import {
    HOUSEKEEPING_STATUS_FILTER_LABELS,
    HOUSEKEEPING_TYPE_FILTER_LABELS,
    PRIORITY_FILTER_LABELS,
    type HousekeepingStatusFilter,
    type HousekeepingTaskFiltersState,
    type HousekeepingTaskTypeFilter,
    type PriorityFilter,
} from "@/types/housekeeping";

interface HousekeepingTaskFiltersProps {
    filters: HousekeepingTaskFiltersState;
    errors?: Partial<Record<keyof HousekeepingTaskFiltersState, string>>;
    onApply: (filters: HousekeepingTaskFiltersState) => void;
}

const STATUS_OPTIONS: HousekeepingStatusFilter[] = [
    "ALL",
    "TODO",
    "IN_PROGRESS",
    "DONE",
    "CANCELLED",
];

const TYPE_OPTIONS: HousekeepingTaskTypeFilter[] = [
    "ALL",
    "STANDARD_CLEANING",
    "DEEP_CLEANING",
    "INSPECTION",
    "LIGHT_MAINTENANCE",
];

const PRIORITY_OPTIONS: PriorityFilter[] = [
    "ALL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "URGENT",
];

export function HousekeepingTaskFilters({
    filters,
    errors = {},
    onApply,
}: HousekeepingTaskFiltersProps) {
    function updateField<K extends keyof HousekeepingTaskFiltersState>(
        field: K,
        value: HousekeepingTaskFiltersState[K]
    ) {
        onApply({
            ...filters,
            [field]: value,
        });
    }

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

                    <PopoverPanel className="absolute right-0 top-full z-30 mt-3 w-[min(820px,calc(100vw-2.5rem))] rounded-[20px] border border-[var(--hms-soft-border)] bg-white p-5 shadow-[0_24px_70px_rgba(13,9,7,0.14)]">
                        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                    <HmsSelect
                        id="housekeeping-status-filter"
                        label="Statut"
                        value={filters.status}
                        onChange={(event) =>
                            updateField(
                                "status",
                                event.target.value as HousekeepingStatusFilter
                            )
                        }
                        error={errors.status}
                    >
                        {STATUS_OPTIONS.map((status) => (
                            <option key={status} value={status}>
                                {HOUSEKEEPING_STATUS_FILTER_LABELS[status]}
                            </option>
                        ))}
                    </HmsSelect>

                    <HmsSelect
                        id="housekeeping-type-filter"
                        label="Type"
                        value={filters.type}
                        onChange={(event) =>
                            updateField(
                                "type",
                                event.target.value as HousekeepingTaskTypeFilter
                            )
                        }
                        error={errors.type}
                    >
                        {TYPE_OPTIONS.map((type) => (
                            <option key={type} value={type}>
                                {HOUSEKEEPING_TYPE_FILTER_LABELS[type]}
                            </option>
                        ))}
                    </HmsSelect>

                    <HmsSelect
                        id="housekeeping-priority-filter"
                        label="Priorité"
                        value={filters.priority}
                        onChange={(event) =>
                            updateField(
                                "priority",
                                event.target.value as PriorityFilter
                            )
                        }
                        error={errors.priority}
                    >
                        {PRIORITY_OPTIONS.map((priority) => (
                            <option key={priority} value={priority}>
                                {PRIORITY_FILTER_LABELS[priority]}
                            </option>
                        ))}
                    </HmsSelect>

                    <HmsInput
                        id="housekeeping-room-filter"
                        label="Chambre"
                        type="text"
                        inputMode="numeric"
                        value={filters.roomId}
                        onChange={(event) => updateField("roomId", event.target.value)}
                        placeholder="201"
                        error={errors.roomId}
                    />

                    <HmsInput
                        id="housekeeping-agent-filter"
                        label="Agent"
                        type="text"
                        inputMode="numeric"
                        value={filters.agentId}
                        onChange={(event) => updateField("agentId", event.target.value)}
                        placeholder="101"
                        error={errors.agentId}
                    />

                    <HmsInput
                        id="housekeeping-date-filter"
                        label="Date planifiée"
                        type="date"
                        value={filters.scheduledDate}
                        onChange={(event) =>
                            updateField("scheduledDate", event.target.value)
                        }
                        error={errors.scheduledDate}
                    />
                        </div>
                    </PopoverPanel>
                </>
            )}
        </Popover>
    );
}
