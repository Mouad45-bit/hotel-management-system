"use client";

import type { FormEvent } from "react";
import { HmsCard } from "@/components/hms/HmsCard";
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
        <HmsCard>
            <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                    <h3 className="text-sm font-semibold text-zinc-950">
                        Filtres
                    </h3>
                    <p className="mt-1 text-sm text-zinc-500">
                        Filtrer par statut, type, priorité, chambre, agent ou date planifiée.
                    </p>
                </div>

                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
                    <div>
                        <label className="text-xs font-medium text-zinc-600">
                            Statut
                        </label>
                        <select
                            value={filters.status}
                            onChange={(event) =>
                                updateField(
                                    "status",
                                    event.target.value as HousekeepingStatusFilter
                                )
                            }
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        >
                            {STATUS_OPTIONS.map((status) => (
                                <option key={status} value={status}>
                                    {HOUSEKEEPING_STATUS_FILTER_LABELS[status]}
                                </option>
                            ))}
                        </select>
                        {errors.status && (
                            <p className="mt-1 text-xs text-red-600">{errors.status}</p>
                        )}
                    </div>

                    <div>
                        <label className="text-xs font-medium text-zinc-600">
                            Type
                        </label>
                        <select
                            value={filters.type}
                            onChange={(event) =>
                                updateField(
                                    "type",
                                    event.target.value as HousekeepingTaskTypeFilter
                                )
                            }
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        >
                            {TYPE_OPTIONS.map((type) => (
                                <option key={type} value={type}>
                                    {HOUSEKEEPING_TYPE_FILTER_LABELS[type]}
                                </option>
                            ))}
                        </select>
                        {errors.type && (
                            <p className="mt-1 text-xs text-red-600">{errors.type}</p>
                        )}
                    </div>

                    <div>
                        <label className="text-xs font-medium text-zinc-600">
                            Priorité
                        </label>
                        <select
                            value={filters.priority}
                            onChange={(event) =>
                                updateField(
                                    "priority",
                                    event.target.value as PriorityFilter
                                )
                            }
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        >
                            {PRIORITY_OPTIONS.map((priority) => (
                                <option key={priority} value={priority}>
                                    {PRIORITY_FILTER_LABELS[priority]}
                                </option>
                            ))}
                        </select>
                        {errors.priority && (
                            <p className="mt-1 text-xs text-red-600">{errors.priority}</p>
                        )}
                    </div>

                    <div>
                        <label className="text-xs font-medium text-zinc-600">
                            Chambre ID
                        </label>
                        <input
                            type="text"
                            inputMode="numeric"
                            value={filters.roomId}
                            onChange={(event) => updateField("roomId", event.target.value)}
                            placeholder="201"
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        />
                        {errors.roomId && (
                            <p className="mt-1 text-xs text-red-600">{errors.roomId}</p>
                        )}
                    </div>

                    <div>
                        <label className="text-xs font-medium text-zinc-600">
                            Agent ID
                        </label>
                        <input
                            type="text"
                            inputMode="numeric"
                            value={filters.agentId}
                            onChange={(event) => updateField("agentId", event.target.value)}
                            placeholder="101"
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        />
                        {errors.agentId && (
                            <p className="mt-1 text-xs text-red-600">{errors.agentId}</p>
                        )}
                    </div>

                    <div>
                        <label className="text-xs font-medium text-zinc-600">
                            Date planifiée
                        </label>
                        <input
                            type="date"
                            value={filters.scheduledDate}
                            onChange={(event) =>
                                updateField("scheduledDate", event.target.value)
                            }
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        />
                        {errors.scheduledDate && (
                            <p className="mt-1 text-xs text-red-600">
                                {errors.scheduledDate}
                            </p>
                        )}
                    </div>
                </div>

                <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
                    <button
                        type="button"
                        onClick={onReset}
                        disabled={loading}
                        className="rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                        Réinitialiser
                    </button>
                    <button
                        type="submit"
                        disabled={loading}
                        className="rounded-xl bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                        Appliquer les filtres
                    </button>
                </div>
            </form>
        </HmsCard>
    );
}
