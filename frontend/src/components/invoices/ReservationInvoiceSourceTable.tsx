"use client";

import {
    CheckCircleIcon,
    ClockIcon,
    ExclamationTriangleIcon,
} from "@heroicons/react/24/outline";
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
            icon: ExclamationTriangleIcon,
            className: "bg-amber-50 text-amber-700 ring-amber-200",
        };
    }

    if (source.reservationStatus !== "CHECKED_OUT") {
        return {
            label: "Non terminée",
            icon: ClockIcon,
            className: "bg-zinc-100 text-zinc-600 ring-zinc-200",
        };
    }

    return {
        label: "Prête à facturer",
        icon: CheckCircleIcon,
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
                    <p className="text-sm font-semibold text-zinc-950">
                        Aucune réservation disponible
                    </p>

                    <p className="mt-1 text-sm text-zinc-500">
                        Les réservations terminées apparaîtront ici pour générer une
                        facture.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-zinc-200">
                <thead className="bg-zinc-50">
                    <tr>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Réservation
                        </th>

                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Client
                        </th>

                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Séjour
                        </th>

                        <th className="px-6 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Estimation HT
                        </th>

                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            État
                        </th>

                        <th className="px-6 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Action
                        </th>
                    </tr>
                </thead>

                <tbody className="divide-y divide-zinc-100 bg-white">
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
                                    selected && "bg-stone-50",
                                    !selected && "hover:bg-zinc-50"
                                )}
                            >
                                <td className="whitespace-nowrap px-6 py-4">
                                    <p className="text-sm font-semibold text-zinc-950">
                                        #{source.reservationId}
                                    </p>

                                    <p className="mt-1 text-xs text-zinc-500">
                                        {
                                            RESERVATION_STATUS_LABELS[
                                                source.reservationStatus
                                            ]
                                        }
                                    </p>
                                </td>

                                <td className="whitespace-nowrap px-6 py-4">
                                    <p className="text-sm font-medium text-zinc-900">
                                        {source.clientFullName}
                                    </p>

                                    <p className="mt-1 text-xs text-zinc-500">
                                        Client #{source.clientId}
                                    </p>
                                </td>

                                <td className="min-w-72 px-6 py-4">
                                    <p className="text-sm font-medium text-zinc-900">
                                        Chambre {source.roomNumber}
                                    </p>

                                    <p className="mt-1 text-xs text-zinc-500">
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

                                    <p className="mt-1 text-xs text-zinc-500">
                                        {source.nights} nuit(s) ×{" "}
                                        <InvoiceAmount
                                            amount={source.pricePerNight}
                                            variant="muted"
                                            className="text-xs"
                                        />
                                    </p>
                                </td>

                                <td className="whitespace-nowrap px-6 py-4 text-right">
                                    <InvoiceAmount
                                        amount={subtotal}
                                        variant="strong"
                                        className="text-sm"
                                    />
                                </td>

                                <td className="whitespace-nowrap px-6 py-4">
                                    <span
                                        className={cn(
                                            "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
                                            badge.className
                                        )}
                                    >
                                        <BadgeIcon className="h-3.5 w-3.5" />
                                        {badge.label}
                                    </span>
                                </td>

                                <td className="whitespace-nowrap px-6 py-4 text-right">
                                    <button
                                        type="button"
                                        onClick={() => onSelect(source)}
                                        disabled={!available}
                                        className={cn(
                                            "rounded-xl px-3 py-2 text-xs font-semibold transition",
                                            selected &&
                                                "bg-stone-900 text-white",
                                            !selected &&
                                                available &&
                                                "border border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50",
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
