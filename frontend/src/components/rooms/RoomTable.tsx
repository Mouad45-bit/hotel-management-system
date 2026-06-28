import Link from "next/link";
import { BedDouble, Eye, Pencil, Power, RefreshCcw } from "lucide-react";
import type { Room, RoomType } from "@/types/room";
import { RoomStatusBadge } from "./RoomStatusBadge";

interface RoomTableProps {
    rooms: Room[];
    onDeleteClick: (room: Room) => void;
    onActivateClick?: (room: Room) => void;
}

const TYPE_LABELS: Record<RoomType, string> = {
    SINGLE: "Single", DOUBLE: "Double", TWIN: "Twin",
    SUITE: "Suite", FAMILY: "Family", DELUXE: "Deluxe",
};

export function RoomTable({ rooms, onDeleteClick, onActivateClick }: RoomTableProps) {
    if (rooms.length === 0) {
        return (
            <div className="flex min-h-60 items-center justify-center px-6 py-12">
                <div className="text-center">
                    <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <BedDouble className="h-6 w-6" strokeWidth={1.8} />
                    </div>
                    <p className="mt-4 text-sm font-semibold text-[var(--hms-text)]">Aucune chambre trouvée</p>
                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">Aucune chambre ne correspond aux filtres sélectionnés.</p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="w-full table-auto border-collapse">
                <thead className="bg-slate-50">
                    <tr>
                        {["Numéro", "Type", "Étage", "Capacité", "Prix / nuit", "Statut", "Active"].map((h) => (
                            <th key={h} className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">{h}</th>
                        ))}
                        <th className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Actions</th>
                    </tr>
                </thead>
                <tbody className="bg-white">
                    {rooms.map((room) => (
                        <tr key={room.id} className="transition-colors hover:bg-slate-50">
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3">
                                <span className="inline-flex items-center rounded-lg bg-slate-100 px-2.5 py-1 text-xs font-bold text-[var(--hms-text)]">
                                    {room.number}
                                </span>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-sm font-bold uppercase text-[var(--hms-text)]">
                                {TYPE_LABELS[room.type] ?? room.type}
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-sm text-[var(--hms-text-muted)]">{room.floor}</td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-sm text-[var(--hms-text-muted)]">{room.capacity} pers.</td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-sm font-semibold text-[var(--hms-text)]">{room.pricePerNight} DH</td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3">
                                <RoomStatusBadge status={room.status} />
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3">
                                <span className={room.active ? "text-sm font-semibold text-emerald-600" : "text-sm font-semibold text-red-500"}>
                                    {room.active ? "Oui" : "Non"}
                                </span>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3">
                                <div className="flex justify-end gap-1.5">
                                    <Link
                                        href={`/rooms/${room.id}`}
                                        className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                        title="Voir le détail"
                                    >
                                        <Eye className="h-4 w-4" strokeWidth={1.8} />
                                    </Link>
                                    <Link
                                        href={`/rooms/${room.id}/edit`}
                                        className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                        title="Modifier"
                                    >
                                        <Pencil className="h-4 w-4" strokeWidth={1.8} />
                                    </Link>
                                    {room.active ? (
                                        <button
                                            onClick={() => onDeleteClick(room)}
                                            className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-orange-200 bg-white text-orange-600 transition-colors hover:bg-orange-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                            title="Désactiver la chambre"
                                        >
                                            <Power className="h-4 w-4" strokeWidth={1.8} />
                                        </button>
                                    ) : (
                                        <button
                                            onClick={() => onActivateClick?.(room)}
                                            className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-emerald-200 bg-white text-emerald-700 transition-colors hover:bg-emerald-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                            title="Réactiver la chambre"
                                        >
                                            <RefreshCcw className="h-4 w-4" strokeWidth={1.8} />
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
