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
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-[var(--hms-soft-border)]">
                <thead className="bg-slate-50">
                    <tr>
                        <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Réservation
                        </th>

                        <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Client
                        </th>

                        <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Séjour
                        </th>

                        <th className="px-6 py-4 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Estimation HT
                        </th>

                        <th className="px-6 py-4 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            État
                        </th>

                        <th className="px-6 py-4 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Action
                        </th>
                    </tr>
                </thead>

                <tbody className="divide-y divide-[var(--hms-soft-border)] bg-white">
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
                                    "transition",
                                    selected && "bg-slate-50",
                                    !selected && "hover:bg-zinc-50"
                                )}
                            >
                                <td className="whitespace-nowrap px-6 py-5">
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

                                <td className="whitespace-nowrap px-6 py-5">
                                    <p className="text-sm font-semibold text-[var(--hms-text)]">
                                        {source.clientFullName}
                                    </p>

                                    <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                        Client #{source.clientId}
                                    </p>
                                </td>

                                <td className="min-w-72 px-6 py-5">
                                    <p className="text-sm font-semibold text-[var(--hms-text)]">
                                        Chambre {source.roomNumber}
                                    </p>

                                    <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                        <InvoiceDate
                                            value={source.checkInDate}
                                            className="text-xs text-zinc-500"
                                        />{" "}
                                        →{" "}
                                        <InvoiceDate
                                            value={source.checkOutDate}
                                            className="text-xs text-zinc-500"
                                        />
                                    </p>

                                    <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                        {source.nights} nuit(s) ×{" "}
                                        <InvoiceAmount
                                            amount={source.pricePerNight}
                                            variant="muted"
                                            className="text-xs"
                                        />
                                    </p>
                                </td>

                                <td className="whitespace-nowrap px-6 py-5 text-right">
                                    <InvoiceAmount
                                        amount={subtotal}
                                        variant="strong"
                                        className="text-sm"
                                    />
                                </td>

                                <td className="whitespace-nowrap px-6 py-5">
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

                                <td className="whitespace-nowrap px-6 py-5 text-right">
                                    <button
                                        type="button"
                                        onClick={() => onSelect(source)}
                                        disabled={!available}
                                        className={cn(
                                            "rounded-xl px-3 py-2 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2",
                                            selected &&
                                                "cursor-pointer bg-[var(--hms-primary)] text-white",
                                            !selected &&
                                                available &&
                                                "cursor-pointer border border-[var(--hms-border)] bg-white text-[var(--hms-text)] hover:bg-slate-50",
                                            !available &&
                                                "cursor-not-allowed border border-zinc-200 bg-zinc-50 text-zinc-400"
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
