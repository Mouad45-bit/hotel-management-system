"use client";

import {
    Room,
    RoomStatus,
    ROOM_TYPE_LABELS,
    ROOM_STATUS_LABELS,
    ROOM_STATUSES,
} from "@/types/room";
import { RoomStatusBadge } from "@/components/rooms/RoomStatusBadge";
import { EyeIcon, PencilSquareIcon, TrashIcon } from "@heroicons/react/24/outline";

interface RoomTableProps {
    rooms: Room[];
    onView: (room: Room) => void;
    onEdit: (room: Room) => void;
    onDelete: (room: Room) => void;
    onStatusChange: (room: Room, newStatus: RoomStatus) => void;
}

export function RoomTable({ rooms, onView, onEdit, onDelete, onStatusChange }: RoomTableProps) {
    // ─── État vide ───────────────────────────────────────────────────────────
    if (rooms.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center py-12 text-center">
                <p className="text-sm font-medium text-zinc-900">Aucune chambre trouvée</p>
                <p className="mt-1 text-sm text-zinc-500">
                    Ajustez vos filtres ou ajoutez une nouvelle chambre.
                </p>
            </div>
        );
    }

    // ─── Tableau ─────────────────────────────────────────────────────────────
    return (
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-zinc-200">
                <thead>
                <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500">
                        Numéro
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500">
                        Type
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500">
                        Étage
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500">
                        Capacité
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500">
                        Prix / nuit
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500">
                        Statut
                    </th>
                    <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-zinc-500">
                        Actions
                    </th>
                </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100">
                {rooms.map(room => (
                    <tr key={room.id} className="hover:bg-zinc-50 transition-colors">
                        <td className="whitespace-nowrap px-4 py-3 text-sm font-medium text-zinc-900">
                            {room.number}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 text-sm text-zinc-600">
                            {ROOM_TYPE_LABELS[room.type]}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 text-sm text-zinc-600">
                            {room.floor}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 text-sm text-zinc-600">
                            {room.capacity} pers.
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 text-sm text-zinc-600">
                            {room.pricePerNight.toFixed(2)} €
                        </td>
                        <td className="whitespace-nowrap px-4 py-3">
                            {/* Select de changement de statut rapide */}
                            <select
                                value={room.status}
                                onChange={e => onStatusChange(room, e.target.value as RoomStatus)}
                                className="appearance-none border-none bg-transparent p-0 text-sm focus:outline-none focus:ring-0 cursor-pointer"
                            >
                                {ROOM_STATUSES.map(s => (
                                    <option key={s} value={s}>{ROOM_STATUS_LABELS[s]}</option>
                                ))}
                            </select>
                            {/* Badge visuel sous le select */}
                            <div className="mt-1">
                                <RoomStatusBadge status={room.status} />
                            </div>
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 text-right">
                            <div className="flex items-center justify-end gap-2">
                                <button
                                    onClick={() => onView(room)}
                                    className="rounded-md p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 transition-colors"
                                    title="Voir le détail"
                                >
                                    <EyeIcon className="h-4 w-4" />
                                </button>
                                <button
                                    onClick={() => onEdit(room)}
                                    className="rounded-md p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-blue-600 transition-colors"
                                    title="Modifier"
                                >
                                    <PencilSquareIcon className="h-4 w-4" />
                                </button>
                                <button
                                    onClick={() => onDelete(room)}
                                    className="rounded-md p-1.5 text-zinc-400 hover:bg-red-50 hover:text-red-600 transition-colors"
                                    title="Supprimer"
                                >
                                    <TrashIcon className="h-4 w-4" />
                                </button>
                            </div>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );
}
