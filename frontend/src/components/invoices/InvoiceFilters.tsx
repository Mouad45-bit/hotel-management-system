"use client";

import type { FormEvent } from "react";
import { HmsCard } from "@/components/hms/HmsCard";
import {
    INVOICE_STATUS_FILTER_LABELS,
    type InvoiceFiltersState,
    type InvoiceStatusFilter,
} from "@/types/invoice";

interface InvoiceFiltersProps {
    filters: InvoiceFiltersState;
    errors?: Partial<Record<keyof InvoiceFiltersState, string>>;
    loading?: boolean;
    onApply: (filters: InvoiceFiltersState) => void;
    onReset: () => void;
}

const STATUS_OPTIONS: InvoiceStatusFilter[] = [
    "ALL",
    "DRAFT",
    "ISSUED",
    "PAID",
    "CANCELLED",
    "REFUNDED",
];

export function InvoiceFilters({
    filters,
    errors = {},
    loading = false,
    onApply,
    onReset,
}: InvoiceFiltersProps) {
    function updateField<K extends keyof InvoiceFiltersState>(
        field: K,
        value: InvoiceFiltersState[K]
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
                <div className="flex flex-col gap-1">
                    <h3 className="text-sm font-semibold text-zinc-950">
                        Filtres
                    </h3>

                    <p className="text-sm text-zinc-500">
                        Rechercher une facture par numéro, statut, client,
                        réservation ou période.
                    </p>
                </div>

                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
                    <div className="xl:col-span-2">
                        <label className="text-xs font-medium text-zinc-600">
                            Numéro de facture
                        </label>

                        <input
                            type="text"
                            value={filters.number}
                            onChange={(event) =>
                                updateField("number", event.target.value)
                            }
                            placeholder="INV-2026-000001"
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        />

                        {errors.number && (
                            <p className="mt-1 text-xs text-red-600">
                                {errors.number}
                            </p>
                        )}
                    </div>

                    <div>
                        <label className="text-xs font-medium text-zinc-600">
                            Statut
                        </label>

                        <select
                            value={filters.status}
                            onChange={(event) =>
                                updateField(
                                    "status",
                                    event.target.value as InvoiceStatusFilter
                                )
                            }
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        >
                            {STATUS_OPTIONS.map((status) => (
                                <option key={status} value={status}>
                                    {INVOICE_STATUS_FILTER_LABELS[status]}
                                </option>
                            ))}
                        </select>

                        {errors.status && (
                            <p className="mt-1 text-xs text-red-600">
                                {errors.status}
                            </p>
                        )}
                    </div>

                    <div>
                        <label className="text-xs font-medium text-zinc-600">
                            Client ID
                        </label>

                        <input
                            type="text"
                            inputMode="numeric"
                            value={filters.clientId}
                            onChange={(event) =>
                                updateField("clientId", event.target.value)
                            }
                            placeholder="8"
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        />

                        {errors.clientId && (
                            <p className="mt-1 text-xs text-red-600">
                                {errors.clientId}
                            </p>
                        )}
                    </div>

                    <div>
                        <label className="text-xs font-medium text-zinc-600">
                            Réservation ID
                        </label>

                        <input
                            type="text"
                            inputMode="numeric"
                            value={filters.reservationId}
                            onChange={(event) =>
                                updateField("reservationId", event.target.value)
                            }
                            placeholder="15"
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        />

                        {errors.reservationId && (
                            <p className="mt-1 text-xs text-red-600">
                                {errors.reservationId}
                            </p>
                        )}
                    </div>

                    <div>
                        <label className="text-xs font-medium text-zinc-600">
                            Du
                        </label>

                        <input
                            type="date"
                            value={filters.from}
                            onChange={(event) =>
                                updateField("from", event.target.value)
                            }
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        />

                        {errors.from && (
                            <p className="mt-1 text-xs text-red-600">
                                {errors.from}
                            </p>
                        )}
                    </div>

                    <div>
                        <label className="text-xs font-medium text-zinc-600">
                            Au
                        </label>

                        <input
                            type="date"
                            value={filters.to}
                            onChange={(event) =>
                                updateField("to", event.target.value)
                            }
                            className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                        />

                        {errors.to && (
                            <p className="mt-1 text-xs text-red-600">
                                {errors.to}
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
