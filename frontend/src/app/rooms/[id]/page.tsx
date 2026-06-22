'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { RoomStatusBadge } from '@/components/rooms/RoomStatusBadge';
import { DeleteRoomDialog } from '@/components/rooms/DeleteRoomDialog';
import { ChangeRoomStatusDialog } from '@/components/rooms/ChangeRoomStatusDialog'; // <-- NOUVEAU
import { RoomService } from '@/services/room.service';
import { Room, RoomStatus, RoomType } from '@/types/room';
import {
    AlertCircle,
    BedDouble,
    Building2,
    CalendarPlus,
    Hash,
    History,
    Pencil,
    Power,
    RefreshCcw,
    Repeat,
    Users,
} from 'lucide-react';

const TYPE_LABELS: Record<RoomType, string> = {
    SINGLE: "Single", DOUBLE: "Double", TWIN: "Twin",
    SUITE: "Suite", FAMILY: "Family", DELUXE: "Deluxe",
};

export default function RoomDetailPage() {
    const router = useRouter();
    const params = useParams<{ id: string }>();
    const id = Number(params.id);

    const [room, setRoom] = useState<Room | null>(null);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // États des modales
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [isDeleting, setIsDeleting] = useState(false);
    const [statusDialogOpen, setStatusDialogOpen] = useState(false); // <-- NOUVEAU

    const fetchRoom = () => {
        setLoading(true);
        RoomService.getRoomById(id)
            .then(setRoom)
            .catch((err) => setError(err instanceof Error ? err.message : 'Chambre introuvable'))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        fetchRoom();
    }, [id]);

    const handleDeactivate = async () => {
        setIsDeleting(true);
        try {
            await RoomService.deleteRoom(id);
            router.push('/rooms');
            router.refresh();
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur lors de la désactivation");
            setConfirmDelete(false);
        } finally {
            setIsDeleting(false);
        }
    };

    // <-- NOUVELLE FONCTION POUR LE PATCH DU STATUT
    const handleStatusChange = async (newStatus: RoomStatus) => {
        await RoomService.updateStatus(id, newStatus);
        fetchRoom(); // Recharge la page pour afficher le nouveau badge
    };

    if (isLoading) {
        return (
            <AppLayout>
                <div className="flex items-center justify-center py-24 text-zinc-400">
                    <RefreshCcw size={18} className="mr-2 animate-spin" />
                    Chargement de la chambre...
                </div>
            </AppLayout>
        );
    }

    if (error || !room) {
        return (
            <AppLayout>
                <div className="flex items-start gap-4 rounded-2xl border border-red-200 bg-red-50 p-6">
                    <AlertCircle className="mt-0.5 shrink-0 text-red-500" size={20} />
                    <div>
                        <p className="font-semibold text-red-700">Chambre introuvable</p>
                        <p className="mt-1 text-sm text-red-600">{error}</p>
                    </div>
                </div>
            </AppLayout>
        );
    }

    const tiles = [
        { icon: Hash, label: "Numéro", value: room.number },
        { icon: BedDouble, label: "Type", value: TYPE_LABELS[room.type] ?? room.type },
        { icon: Building2, label: "Étage", value: `Étage ${room.floor}` },
        { icon: Users, label: "Capacité", value: `${room.capacity} personne${room.capacity > 1 ? 's' : ''}` },
    ];

    return (
        <AppLayout>
            <PageHeader
                backHref="/rooms"
                eyebrow={`CH-${room.number}`}
                title={`Chambre ${room.number}`}
                description="Tableau de bord de la chambre : informations générales, statut métier, disponibilité administrative et accès aux actions principales."
                actions={
                    <>
                        <Link
                            href={`/rooms/${id}/edit`}
                            className="inline-flex items-center gap-2 rounded-2xl bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-zinc-800"
                        >
                            <Pencil size={16} />
                            Modifier
                        </Link>
                        <button
                            onClick={() => setConfirmDelete(true)}
                            className="inline-flex items-center gap-2 rounded-2xl bg-orange-500 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-orange-600"
                        >
                            <Power size={16} />
                            Désactiver
                        </button>
                    </>
                }
            />

            <div className="rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
                <div className="flex items-center justify-between">
                    <RoomStatusBadge status={room.status} />
                    <span
                        className={
                            room.active
                                ? "inline-flex items-center rounded-full bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-700 ring-1 ring-inset ring-emerald-200"
                                : "inline-flex items-center rounded-full bg-red-50 px-3 py-1 text-xs font-medium text-red-700 ring-1 ring-inset ring-red-200"
                        }
                    >
                        {room.active ? "Active" : "Inactive"}
                    </span>
                </div>

                {room.description && (
                    <p className="mt-5 text-base text-zinc-600">{room.description}</p>
                )}

                <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
                    {tiles.map(({ icon: Icon, label, value }) => (
                        <div key={label} className="rounded-2xl border border-zinc-100 bg-zinc-50 p-5">
                            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white text-zinc-500 shadow-sm">
                                <Icon size={18} />
                            </div>
                            <p className="mt-4 text-xs font-semibold uppercase tracking-wider text-zinc-400">
                                {label}
                            </p>
                            <p className="mt-1 text-lg font-bold text-zinc-900">{value}</p>
                        </div>
                    ))}
                </div>
            </div>

            <div className="flex flex-col gap-6 rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200 lg:flex-row lg:items-center lg:justify-between">
                <div>
                    <p className="text-sm font-medium text-zinc-500">Prix par nuit</p>
                    <p className="mt-1 text-4xl font-bold text-zinc-950">{room.pricePerNight} DH</p>
                </div>

                <div className="flex flex-wrap gap-3">
                    {/* LE BOUTON EST MAINTENANT ACTIF */}
                    <button
                        onClick={() => setStatusDialogOpen(true)}
                        className="inline-flex items-center gap-2 rounded-2xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50"
                    >
                        <Repeat size={16} />
                        Changer statut
                    </button>

                    <Link
                        href={`/reservations?roomId=${id}`}
                        className="inline-flex items-center gap-2 rounded-2xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50"
                    >
                        <History size={16} />
                        Historique
                    </Link>
                    <Link
                        href={`/reservations/create?roomId=${id}`}
                        className="inline-flex items-center gap-2 rounded-2xl bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-zinc-800"
                    >
                        <CalendarPlus size={16} />
                        Réserver
                    </Link>
                </div>
            </div>

            <DeleteRoomDialog
                isOpen={confirmDelete}
                onClose={() => setConfirmDelete(false)}
                onConfirm={handleDeactivate}
                roomNumber={room.number}
                isLoading={isDeleting}
            />

            {/* NOTRE NOUVELLE MODALE */}
            <ChangeRoomStatusDialog
                isOpen={statusDialogOpen}
                onClose={() => setStatusDialogOpen(false)}
                onConfirm={handleStatusChange}
                currentStatus={room.status}
                roomNumber={room.number}
            />
        </AppLayout>
    );
}
