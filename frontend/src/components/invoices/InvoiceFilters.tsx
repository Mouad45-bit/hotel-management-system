"use client";

import { Popover, PopoverButton, PopoverPanel } from "@headlessui/react";
import { ListFilter, Search } from "lucide-react";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
import { cn } from "@/lib/utils";
import {
    INVOICE_STATUS_FILTER_LABELS,
    type InvoiceFiltersState,
    type InvoiceStatusFilter,
} from "@/types/invoice";

interface InvoiceFiltersProps {
    filters: InvoiceFiltersState;
    errors?: Partial<Record<keyof InvoiceFiltersState, string>>;
    onApply: (filters: InvoiceFiltersState) => void;
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
    onApply,
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

                    <PopoverPanel className="absolute right-0 top-full z-30 mt-3 w-[min(760px,calc(100vw-2.5rem))] rounded-[20px] border border-[var(--hms-soft-border)] bg-white p-5 shadow-[0_24px_70px_rgba(13,9,7,0.14)]">
                        <div className="space-y-4">
                            <div className="grid gap-4 md:grid-cols-3">
                                <div className="relative">
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
                            </div>

                            <div className="grid gap-4 md:grid-cols-3">
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
                        </div>
                    </PopoverPanel>
                </>
            )}
        </Popover>
    );
}
