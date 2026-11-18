"use client";

import {
    CircleCheckBig,
    Clock3,
    FileText,
    TriangleAlert,
} from "lucide-react";
import { InvoiceAmount } from "@/components/invoices/InvoiceAmount";
import { InvoiceDate } from "@/components/invoices/InvoiceDate";
import { cn } from "@/lib/utils";
import type { ReservationInvoiceSource } from "@/types/invoice";

interface ReservationInvoiceSourceTableProps {
    sources: ReservationInvoiceSource[];
    selectedReservationId?: number | null;
    onSelect: (source: ReservationInvoiceSource) => void;
}

const RESERVATION_STATUS_LABELS: Record<
    ReservationInvoiceSource["reservationStatus"],
    string
> = {
    CREATED: "Créée",
    CONFIRMED: "Confirmée",
    CHECKED_IN: "Check-in effectué",
    CHECKED_OUT: "Terminée",
    CANCELLED: "Annulée",
    NO_SHOW: "No-show",
};

function canGenerateInvoice(source: ReservationInvoiceSource): boolean {
    return source.reservationStatus === "CHECKED_OUT" && !source.hasActiveInvoice;
}

function getSourceBadge(source: ReservationInvoiceSource) {
    if (source.hasActiveInvoice) {
        return {
            label: "Facture existante",
            icon: TriangleAlert,
            className: "bg-amber-50 text-amber-700 ring-amber-200",
        };
    }

    if (source.reservationStatus !== "CHECKED_OUT") {
        return {
            label: "Non terminée",
            icon: Clock3,
            className: "bg-zinc-100 text-zinc-600 ring-zinc-200",
        };
    }

    return {
        label: "Prête à facturer",
        icon: CircleCheckBig,
        className: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    };
}

export function ReservationInvoiceSourceTable({
    sources,
    selectedReservationId,
    onSelect,
}: ReservationInvoiceSourceTableProps) {
    if (sources.length === 0) {
        return (
            <div className="flex min-h-52 items-center justify-center px-6 py-10 text-center">
                <div>
                    <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <FileText aria-hidden="true" className="h-6 w-6" strokeWidth={1.8} />
                    </div>

                    <p className="mt-4 text-sm font-bold text-[var(--hms-text)]">
                        Aucune réservation disponible
                    </p>

                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">
                        Les réservations terminées apparaîtront ici pour générer une
                        facture.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div>
            <table className="w-full table-fixed border-collapse">
                <thead className="hidden bg-slate-50 xl:table-header-group">
                    <tr>
                        <th className="w-[12%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Réservation
                        </th>

                        <th className="w-[14%] border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Client
                        </th>

                        <th className="w-[11%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Chambre
                        </th>

                        <th className="w-[16%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Séjour
                        </th>

                        <th className="w-[6%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Nuits
                        </th>

                        <th className="w-[14%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Estimation HT
                        </th>

                        <th className="w-[15%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            État
                        </th>

                        <th className="w-[12%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Action
                        </th>
                    </tr>
                </thead>

                <tbody className="grid gap-3 bg-white p-4 xl:table-row-group xl:p-0">
                    {sources.map((source) => {
                        const selected =
                            selectedReservationId === source.reservationId;

                        const available = canGenerateInvoice(source);
                        const badge = getSourceBadge(source);
                        const BadgeIcon = badge.icon;
                        const subtotal =
                            source.nights * source.pricePerNight;

                        return (
                            <tr
                                key={source.reservationId}
                                className={cn(
                                    "grid gap-x-4 gap-y-3 rounded-2xl border border-[var(--hms-soft-border)] p-4 transition-colors sm:grid-cols-2 xl:table-row xl:rounded-none xl:border-0 xl:p-0",
                                    selected && "bg-slate-50",
                                    !selected && "hover:bg-zinc-50"
                                )}
                            >
                                <td className="min-w-0 xl:whitespace-nowrap xl:border-b xl:border-[var(--hms-soft-border)] xl:px-3 xl:py-4 xl:align-top">
                                    <p className="mb-1 text-xs font-semibold text-[var(--hms-text-muted)] xl:hidden">
                                        Réservation
                                    </p>

                                    <p className="text-sm font-bold text-[var(--hms-text)]">
                                        #{source.reservationId}
                                    </p>

                                    <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                        {
                                            RESERVATION_STATUS_LABELS[
                                                source.reservationStatus
                                            ]
                                        }
                                    </p>
                                </td>

                                <td className="min-w-0 xl:border-b xl:border-[var(--hms-soft-border)] xl:px-3 xl:py-4 xl:align-top">
                                    <p className="mb-1 text-xs font-semibold text-[var(--hms-text-muted)] xl:hidden">
                                        Client
                                    </p>

                                    <p className="text-sm font-semibold text-[var(--hms-text)]">
                                        {source.clientFullName}
                                    </p>

                                    <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                        Client #{source.clientId}
                                    </p>
                                </td>

                                <td className="min-w-0 xl:whitespace-nowrap xl:border-b xl:border-[var(--hms-soft-border)] xl:px-3 xl:py-4 xl:align-top">
                                    <p className="mb-1 text-xs font-semibold text-[var(--hms-text-muted)] xl:hidden">
                                        Chambre
                                    </p>

                                    <p className="text-sm font-semibold text-[var(--hms-text)]">
                                        Chambre {source.roomNumber}
                                    </p>
                                </td>

                                <td className="min-w-0 xl:whitespace-nowrap xl:border-b xl:border-[var(--hms-soft-border)] xl:px-3 xl:py-4 xl:align-top">
                                    <p className="mb-1 text-xs font-semibold text-[var(--hms-text-muted)] xl:hidden">
                                        Séjour
                                    </p>

                                    <p className="text-xs text-[var(--hms-text-muted)]">
                                        Du{" "}
                                        <InvoiceDate
                                            value={source.checkInDate}
                                            className="text-xs text-zinc-500"
                                        />
                                    </p>

                                    <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                        Au{" "}
                                        <InvoiceDate
                                            value={source.checkOutDate}
                                            className="text-xs text-zinc-500"
                                        />
                                    </p>
                                </td>

                                <td className="min-w-0 xl:whitespace-nowrap xl:border-b xl:border-[var(--hms-soft-border)] xl:px-3 xl:py-4 xl:text-center xl:align-top">
                                    <p className="mb-1 text-xs font-semibold text-[var(--hms-text-muted)] xl:hidden">
                                        Nuits
                                    </p>

                                    <p className="text-sm font-semibold text-[var(--hms-text)]">
                                        {source.nights}
                                    </p>
                                </td>

                                <td className="min-w-0 xl:whitespace-nowrap xl:border-b xl:border-[var(--hms-soft-border)] xl:px-3 xl:py-4 xl:text-right xl:align-top">
                                    <p className="mb-1 text-xs font-semibold text-[var(--hms-text-muted)] xl:hidden">
                                        Estimation HT
                                    </p>

                                    <InvoiceAmount
                                        amount={subtotal}
                                        variant="strong"
                                        className="text-sm"
                                    />

                                    <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                        <InvoiceAmount
                                            amount={source.pricePerNight}
                                            variant="muted"
                                            className="text-xs"
                                        />{" "}
                                        / nuit
                                    </p>
                                </td>

                                <td className="min-w-0 xl:whitespace-nowrap xl:border-b xl:border-[var(--hms-soft-border)] xl:px-3 xl:py-4 xl:text-center xl:align-top">
                                    <p className="mb-1 text-xs font-semibold text-[var(--hms-text-muted)] xl:hidden">
                                        État
                                    </p>

                                    <span
                                        className={cn(
                                            "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
                                            badge.className
                                        )}
                                    >
                                        <BadgeIcon aria-hidden="true" className="h-3.5 w-3.5" strokeWidth={1.8} />
                                        {badge.label}
                                    </span>
                                </td>

                                <td className="min-w-0 sm:col-span-2 xl:table-cell xl:whitespace-nowrap xl:border-b xl:border-[var(--hms-soft-border)] xl:px-3 xl:py-4 xl:text-right xl:align-top">
                                    <p className="mb-1 text-xs font-semibold text-[var(--hms-text-muted)] xl:hidden">
                                        Action
                                    </p>

                                    <button
                                        type="button"
                                        onClick={() => onSelect(source)}
                                        disabled={!available}
                                        className={cn(
                                            "inline-flex min-h-10 w-full items-center justify-center rounded-xl border px-3 py-2 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2 sm:w-auto",
                                            selected &&
                                                "cursor-pointer border-[var(--hms-primary)] bg-[var(--hms-primary)] text-white hover:bg-[var(--hms-primary-hover)] active:bg-[var(--hms-primary-active)]",
                                            !selected &&
                                                available &&
                                                "cursor-pointer border-[var(--hms-border)] bg-white text-[var(--hms-text)] hover:bg-slate-50",
                                            !available &&
                                                "cursor-not-allowed border-zinc-200 bg-zinc-50 text-zinc-400"
                                        )}
                                    >
                                        {selected ? "Sélectionnée" : "Sélectionner"}
                                    </button>
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}
