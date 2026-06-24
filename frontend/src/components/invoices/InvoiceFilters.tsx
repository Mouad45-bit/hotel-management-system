"use client";

import type { FormEvent } from "react";
import { Search } from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
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
        <HmsCard className="p-6 lg:p-7">
            <form onSubmit={handleSubmit} className="space-y-5">
                <div className="flex flex-col gap-2">
                    <h3 className="text-base font-bold text-[var(--hms-text)]">
                        Filtres
                    </h3>

                    <p className="text-sm text-[var(--hms-text-muted)]">
                        Rechercher une facture par numéro, statut, client,
                        réservation ou période.
                    </p>
                </div>

                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
                    <div className="relative xl:col-span-2">
                        <Search
                            aria-hidden="true"
                            className="pointer-events-none absolute left-4 top-[42px] h-4 w-4 text-[var(--hms-text-muted)]"
                            strokeWidth={1.8}
                        />

                        <HmsInput
                            id="invoice-number-filter"
                            label="Numéro de facture"
                            type="text"
                            value={filters.number}
                            onChange={(event) =>
                                updateField("number", event.target.value)
                            }
                            placeholder="INV-2026-000001"
                            error={errors.number}
                            className="[&_input]:pl-10"
                        />
                    </div>

                    <HmsSelect
                        id="invoice-status-filter"
                        label="Statut"
                            value={filters.status}
                            onChange={(event) =>
                                updateField(
                                    "status",
                                    event.target.value as InvoiceStatusFilter
                                )
                            }
                        error={errors.status}
                    >
                            {STATUS_OPTIONS.map((status) => (
                                <option key={status} value={status}>
                                    {INVOICE_STATUS_FILTER_LABELS[status]}
                                </option>
                            ))}
                    </HmsSelect>

                    <HmsInput
                        id="invoice-client-filter"
                        label="Client ID"
                            type="text"
                            inputMode="numeric"
                            value={filters.clientId}
                            onChange={(event) =>
                                updateField("clientId", event.target.value)
                            }
                            placeholder="8"
                        error={errors.clientId}
                    />

                    <HmsInput
                        id="invoice-reservation-filter"
                        label="Réservation ID"
                            type="text"
                            inputMode="numeric"
                            value={filters.reservationId}
                            onChange={(event) =>
                                updateField("reservationId", event.target.value)
                            }
                            placeholder="15"
                        error={errors.reservationId}
                    />

                    <HmsInput
                        id="invoice-from-filter"
                        label="Du"
                            type="date"
                            value={filters.from}
                            onChange={(event) =>
                                updateField("from", event.target.value)
                            }
                        error={errors.from}
                    />

                    <HmsInput
                        id="invoice-to-filter"
                        label="Au"
                            type="date"
                            value={filters.to}
                            onChange={(event) =>
                                updateField("to", event.target.value)
                            }
                        error={errors.to}
                    />
                </div>

                <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
                    <HmsButton
                        type="button"
                        variant="secondary"
                        onClick={onReset}
                        disabled={loading}
                    >
                        Réinitialiser
                    </HmsButton>

                    <HmsButton
                        type="submit"
                        disabled={loading}
                    >
                        Appliquer les filtres
                    </HmsButton>
                </div>
            </form>
        </HmsCard>
    );
}
