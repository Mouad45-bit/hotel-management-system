"use client";

import type { FormEvent } from "react";
import { Check, RotateCcw } from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
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
    loading?: boolean;
    onApply: (filters: HousekeepingTaskFiltersState) => void;
    onReset: () => void;
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
    loading = false,
    onApply,
    onReset,
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

    function handleSubmit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();
        onApply(filters);
    }

    return (
        <HmsCard className="p-5">
            <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                    <h3 className="text-lg font-bold text-[var(--hms-text)]">
                        Filtres
                    </h3>

                    <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                        Filtrer par statut, type, priorité, chambre, agent ou date planifiée.
                    </p>
                </div>

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

                <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
                    <HmsButton
                        type="button"
                        variant="secondary"
                        onClick={onReset}
                        disabled={loading}
                    >
                        <RotateCcw aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                        Réinitialiser
                    </HmsButton>

                    <HmsButton type="submit" disabled={loading}>
                        <Check aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                        Appliquer les filtres
                    </HmsButton>
                </div>
            </form>
        </HmsCard>
    );
}
