"use client";

import Link from "next/link";
import { CalendarDays, Eye, Pencil, XCircle } from "lucide-react";
import type { Reservation } from "@/types/reservation";
import { ReservationStatusBadge } from "./ReservationStatusBadge";

interface ReservationTableProps {
    reservations: Reservation[];
    loading?: boolean;
    emptyMessage?: string;
    onCancelClick: (reservation: Reservation) => void;
    roomMap?: Record<number, string>;
    clientMap?: Record<number, string>;
}

const formatDate = (dateStr: string) =>
    new Date(dateStr).toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" });

export function ReservationTable({
    reservations,
    loading = false,
    emptyMessage = "Aucune réservation trouvée.",
    onCancelClick,
    roomMap,
    clientMap,
}: ReservationTableProps) {
    if (loading && reservations.length === 0) {
        return (
            <div className="divide-y divide-[var(--hms-soft-border)]">
                {Array.from({ length: 5 }).map((_, index) => (
                    <div key={index} className="grid gap-3 px-4 py-4 md:grid-cols-8">
                        {Array.from({ length: 8 }).map((__, cellIndex) => (
                            <div
                                key={cellIndex}
                                className="h-5 animate-pulse rounded-lg bg-slate-100"
                            />
                        ))}
                    </div>
                ))}
            </div>
        );
    }

    if (reservations.length === 0) {
        return (
            <div className="flex min-h-60 items-center justify-center px-6 py-12">
                <div className="text-center">
                    <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <CalendarDays className="h-6 w-6" strokeWidth={1.8} />
                    </div>
                    <p className="mt-4 text-sm font-semibold text-[var(--hms-text)]">{emptyMessage}</p>
                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">Aucune réservation ne correspond aux critères.</p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="w-full table-auto border-collapse">
                <thead className="bg-slate-50">
                    <tr>
                        {["ID", "Chambre", "Client", "Arrivée", "Départ", "Prix total", "Statut"].map((h) => (
                            <th
                                key={h}
                                className={`w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)] ${h === "Statut" ? "text-center" : "text-left"}`}
                            >
                                {h}
                            </th>
                        ))}
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Actions</th>
                    </tr>
                </thead>
                <tbody className="bg-white">
                    {reservations.map((r) => (
                        <tr key={r.id} className="transition-colors hover:bg-slate-50">
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-sm font-bold text-[var(--hms-text)]">#{r.id}</td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3">
                                <Link href={`/rooms/${r.roomId}`} className="inline-flex cursor-pointer items-center rounded-lg bg-slate-100 px-2.5 py-1 text-xs font-bold text-[var(--hms-text)] transition-colors hover:bg-slate-200">
                                    {roomMap?.[r.roomId] ? `Chambre ${roomMap[r.roomId]}` : `Chambre #${r.roomId}`}
                                </Link>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3">
                                <Link href={`/clients/${r.clientId}`} className="inline-flex cursor-pointer items-center rounded-lg bg-slate-100 px-2.5 py-1 text-xs font-bold text-[var(--hms-text)] transition-colors hover:bg-slate-200">
                                    {clientMap?.[r.clientId] ?? `Client #${r.clientId}`}
                                </Link>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-sm text-[var(--hms-text-muted)]">{formatDate(r.checkInDate)}</td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-sm text-[var(--hms-text-muted)]">{formatDate(r.checkOutDate)}</td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-sm font-semibold text-[var(--hms-text)]">{r.totalPrice} DH</td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center">
                                <ReservationStatusBadge status={r.status} />
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3">
                                <div className="flex justify-end gap-1.5">
                                    {(r.status === "CREATED" || r.status === "CONFIRMED") && (
                                        <button
                                            type="button"
                                            onClick={() => onCancelClick(r)}
                                            className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-red-200 bg-white text-red-500 transition-colors hover:bg-red-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                            aria-label={`Annuler la réservation ${r.id}`}
                                            title="Annuler"
                                        >
                                            <XCircle className="h-4 w-4" strokeWidth={1.8} />
                                        </button>
                                    )}
                                    {r.status === "CREATED" && (
                                        <Link
                                            href={`/reservations/${r.id}/edit`}
                                            className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                            aria-label={`Modifier la réservation ${r.id}`}
                                            title="Modifier"
                                        >
                                            <Pencil className="h-4 w-4" strokeWidth={1.8} />
                                        </Link>
                                    )}
                                    <Link
                                        href={`/reservations/${r.id}`}
                                        className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                        aria-label={`Voir la réservation ${r.id}`}
                                        title="Voir"
                                    >
                                        <Eye className="h-4 w-4" strokeWidth={1.8} />
                                    </Link>
                                </div>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}
