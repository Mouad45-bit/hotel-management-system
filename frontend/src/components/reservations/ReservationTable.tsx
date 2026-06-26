'use client';

import Link from 'next/link';
import { Reservation } from '@/types/reservation';
import { ReservationStatusBadge } from './ReservationStatusBadge';
import { Eye, Pencil, XCircle } from 'lucide-react';

interface ReservationTableProps {
    reservations: Reservation[];
    onCancelClick: (reservation: Reservation) => void;
}

export function ReservationTable({ reservations, onCancelClick }: ReservationTableProps) {
    if (reservations.length === 0) {
        return (
            <div className="rounded-2xl bg-white p-12 text-center shadow-sm ring-1 ring-zinc-200">
                <p className="text-sm text-zinc-500">Aucune réservation trouvée.</p>
            </div>
        );
    }

    const formatDate = (dateStr: string) => {
        return new Date(dateStr).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' });
    };

    return (
        <div className="overflow-hidden rounded-2xl bg-white shadow-sm ring-1 ring-zinc-200">
            <table className="w-full text-left text-sm">
                <thead>
                    <tr className="border-b border-zinc-100 bg-zinc-50/60">
                        <th className="px-6 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-500">ID</th>
                        <th className="px-6 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-500">Chambre</th>
                        <th className="px-6 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-500">Client</th>
                        <th className="px-6 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-500">Arrivée</th>
                        <th className="px-6 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-500">Départ</th>
                        <th className="px-6 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-500">Prix total</th>
                        <th className="px-6 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-500">Statut</th>
                        <th className="px-6 py-3 text-right text-xs font-semibold uppercase tracking-wider text-zinc-500">Actions</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100">
                    {reservations.map((r) => (
                        <tr key={r.id} className="transition hover:bg-zinc-50/50">
                            <td className="px-6 py-4 font-medium text-zinc-900">#{r.id}</td>
                            <td className="px-6 py-4">
                                <span className="inline-flex items-center rounded-lg bg-zinc-100 px-2.5 py-1 text-xs font-semibold text-zinc-700">
                                    Chambre #{r.roomId}
                                </span>
                            </td>
                            <td className="px-6 py-4">
                                <span className="inline-flex items-center rounded-lg bg-zinc-100 px-2.5 py-1 text-xs font-semibold text-zinc-700">
                                    Client #{r.clientId}
                                </span>
                            </td>
                            <td className="px-6 py-4 text-zinc-600">{formatDate(r.checkInDate)}</td>
                            <td className="px-6 py-4 text-zinc-600">{formatDate(r.checkOutDate)}</td>
                            <td className="px-6 py-4 font-semibold text-zinc-900">{r.totalPrice} DH</td>
                            <td className="px-6 py-4"><ReservationStatusBadge status={r.status} /></td>
                            <td className="px-6 py-4">
                                <div className="flex items-center justify-end gap-1">
                                    <Link
                                        href={`/reservations/${r.id}`}
                                        className="rounded-lg p-2 text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-700"
                                        title="Voir"
                                    >
                                        <Eye size={16} />
                                    </Link>
                                    {r.status === 'CREATED' && (
                                        <Link
                                            href={`/reservations/${r.id}/edit`}
                                            className="rounded-lg p-2 text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-700"
                                            title="Modifier"
                                        >
                                            <Pencil size={16} />
                                        </Link>
                                    )}
                                    {(r.status === 'CREATED' || r.status === 'CONFIRMED') && (
                                        <button
                                            onClick={() => onCancelClick(r)}
                                            className="rounded-lg p-2 text-zinc-400 transition hover:bg-red-50 hover:text-red-600"
                                            title="Annuler"
                                        >
                                            <XCircle size={16} />
                                        </button>
                                    )}
                                </div>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}
