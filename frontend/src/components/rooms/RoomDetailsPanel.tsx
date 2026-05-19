import { Room, ROOM_TYPE_LABELS, ROOM_STATUS_LABELS } from "@/types/room";
import { RoomStatusBadge } from "@/components/rooms/RoomStatusBadge";
import { XMarkIcon } from "@heroicons/react/24/outline";

interface RoomDetailsPanelProps {
    room: Room;
    onClose: () => void;
}

export function RoomDetailsPanel({ room, onClose }: RoomDetailsPanelProps) {
    // Formater les dates ISO en format lisible
    const formatDate = (iso: string) => {
        return new Date(iso).toLocaleDateString("fr-FR", {
            day: "2-digit",
            month: "long",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
        });
    };

    const details = [
        { label: "Numéro", value: room.number },
        { label: "Type", value: ROOM_TYPE_LABELS[room.type] },
        { label: "Étage", value: room.floor },
        { label: "Capacité", value: `${room.capacity} personne${room.capacity > 1 ? "s" : ""}` },
        { label: "Prix par nuit", value: `${room.pricePerNight.toFixed(2)} €` },
        { label: "Créée le", value: formatDate(room.createdAt) },
        { label: "Modifiée le", value: formatDate(room.updatedAt) },
    ];

    return (
        // Fond semi-transparent cliquable pour fermer
        <div
            className="fixed inset-0 z-20 flex justify-end bg-black/20"
            onClick={onClose}
        >
            {/* Panneau latéral — stopPropagation pour ne pas fermer au clic intérieur */}
            <div
                className="h-full w-full max-w-md overflow-y-auto bg-white shadow-xl"
                onClick={e => e.stopPropagation()}
            >
                {/* En-tête */}
                <div className="flex items-center justify-between border-b border-zinc-200 px-6 py-4">
                    <h3 className="text-lg font-semibold text-zinc-900">
                        Chambre {room.number}
                    </h3>
                    <button
                        onClick={onClose}
                        className="rounded-md p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 transition-colors"
                    >
                        <XMarkIcon className="h-5 w-5" />
                    </button>
                </div>

                {/* Corps */}
                <div className="px-6 py-5 space-y-6">
                    {/* Statut mis en avant */}
                    <div>
                        <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">Statut</p>
                        <div className="mt-2">
                            <RoomStatusBadge status={room.status} />
                        </div>
                    </div>

                    {/* Grille de détails */}
                    <div className="grid grid-cols-2 gap-4">
                        {details.map(item => (
                            <div key={item.label}>
                                <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                                    {item.label}
                                </p>
                                <p className="mt-1 text-sm font-medium text-zinc-900">
                                    {item.value}
                                </p>
                            </div>
                        ))}
                    </div>

                    {/* Description */}
                    {room.description && (
                        <div>
                            <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                                Description
                            </p>
                            <p className="mt-2 text-sm leading-relaxed text-zinc-600">
                                {room.description}
                            </p>
                        </div>
                    )}
                </div>

                {/* Pied avec bouton fermer */}
                <div className="border-t border-zinc-200 px-6 py-4">
                    <button
                        onClick={onClose}
                        className="w-full rounded-md border border-zinc-200 bg-white px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-zinc-50"
                    >
                        Fermer
                    </button>
                </div>
            </div>
        </div>
    );
}
