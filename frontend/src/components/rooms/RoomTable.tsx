import Link from "next/link";
import { Room, RoomType } from "@/types/room";
import { Eye, Pencil, Power, RefreshCcw } from "lucide-react";
import { RoomStatusBadge } from "./RoomStatusBadge";

interface RoomTableProps {
    rooms: Room[];
    onDeleteClick: (room: Room) => void;
    // Nouvelle action pour la réactivation
    onActivateClick?: (room: Room) => void;
}

const TYPE_LABELS: Record<RoomType, string> = {
    SINGLE: "Single", DOUBLE: "Double", TWIN: "Twin",
    SUITE: "Suite", FAMILY: "Family", DELUXE: "Deluxe",
};

export function RoomTable({ rooms, onDeleteClick, onActivateClick }: RoomTableProps) {
    return (
        <div className="overflow-hidden rounded-2xl bg-white shadow-sm ring-1 ring-zinc-200">
            <table className="w-full text-left text-sm">
                <thead className="border-b border-zinc-200 text-xs font-semibold uppercase tracking-wider text-zinc-400">
                <tr>
                    <th className="px-6 py-4">Numéro</th>
                    <th className="px-6 py-4">Type</th>
                    <th className="px-6 py-4">Étage</th>
                    <th className="px-6 py-4">Capacité</th>
                    <th className="px-6 py-4">Prix / nuit</th>
                    <th className="px-6 py-4">Statut</th>
                    <th className="px-6 py-4">Active</th>
                    <th className="px-6 py-4 text-right">Actions</th>
                </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100">
                {rooms.length === 0 ? (
                    <tr>
                        <td colSpan={8} className="px-6 py-12 text-center text-zinc-400">
                            Aucune chambre ne correspond aux filtres sélectionnés.
                        </td>
                    </tr>
                ) : (
                    rooms.map((room) => (
                        <tr key={room.id} className="transition hover:bg-zinc-50">
                            <td className="px-6 py-4">
                                    <span className="inline-flex items-center rounded-lg bg-zinc-100 px-3 py-1 text-sm font-bold text-zinc-900">
                                        {room.number}
                                    </span>
                            </td>
                            <td className="px-6 py-4 font-bold uppercase text-zinc-900">
                                {TYPE_LABELS[room.type] ?? room.type}
                            </td>
                            <td className="px-6 py-4 text-zinc-600">{room.floor}</td>
                            <td className="px-6 py-4 text-zinc-600">{room.capacity} pers.</td>
                            <td className="px-6 py-4 font-medium text-zinc-900">{room.pricePerNight} DH</td>
                            <td className="px-6 py-4">
                                <RoomStatusBadge status={room.status} />
                            </td>
                            <td className="px-6 py-4">
                                    <span className={room.active ? "font-semibold text-emerald-600" : "font-semibold text-red-500"}>
                                        {room.active ? "Oui" : "Non"}
                                    </span>
                            </td>
                            <td className="px-6 py-4">
                                <div className="flex items-center justify-end gap-2">
                                    <Link
                                        href={`/rooms/${room.id}`}
                                        className="flex h-8 w-8 items-center justify-center rounded-lg text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-900"
                                        title="Voir le détail"
                                    >
                                        <Eye size={16} />
                                    </Link>
                                    <Link
                                        href={`/rooms/${room.id}`}
                                        className="flex h-8 w-8 items-center justify-center rounded-lg text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-900"
                                        title="Modifier"
                                    >
                                        <Pencil size={16} />
                                    </Link>

                                    {/* LOGIQUE D'AFFICHAGE CONDITIONNEL DES BOUTONS */}
                                    {room.active ? (
                                        <button
                                            onClick={() => onDeleteClick(room)}
                                            className="flex h-8 w-8 items-center justify-center rounded-lg text-orange-500 transition hover:bg-orange-50 hover:text-orange-600"
                                            title="Désactiver la chambre"
                                        >
                                            <Power size={16} />
                                        </button>
                                    ) : (
                                        <button
                                            onClick={() => onActivateClick?.(room)}
                                            className="flex h-8 w-8 items-center justify-center rounded-lg text-emerald-600 transition hover:bg-emerald-50 hover:text-emerald-700"
                                            title="Réactiver la chambre"
                                        >
                                            <RefreshCcw size={16} />
                                        </button>
                                    )}
                                    {/* ------------------------------------------- */}

                                </div>
                            </td>
                        </tr>
                    ))
                )}
                </tbody>
            </table>
        </div>
    );
}
