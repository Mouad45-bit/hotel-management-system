"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { RoomStatusBadge } from "@/components/rooms/RoomStatusBadge";
import { DeleteRoomDialog } from "@/components/rooms/DeleteRoomDialog";
import { ChangeRoomStatusDialog } from "@/components/rooms/ChangeRoomStatusDialog";
import { RoomService } from "@/services/room.service";
import type { Room, RoomStatus, RoomType } from "@/types/room";
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
} from "lucide-react";

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

    const [confirmDelete, setConfirmDelete] = useState(false);
    const [isDeleting, setIsDeleting] = useState(false);
    const [statusDialogOpen, setStatusDialogOpen] = useState(false);

    const fetchRoom = () => {
        setLoading(true);
        RoomService.getRoomById(id)
            .then(setRoom)
            .catch((err) => setError(err instanceof Error ? err.message : "Chambre introuvable"))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        fetchRoom();
    }, [id]);

    const handleDeactivate = async () => {
        setIsDeleting(true);
        try {
            await RoomService.deleteRoom(id);
            router.push("/rooms");
            router.refresh();
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur lors de la désactivation");
            setConfirmDelete(false);
        } finally {
            setIsDeleting(false);
        }
    };

    const handleStatusChange = async (newStatus: RoomStatus) => {
        await RoomService.updateStatus(id, newStatus);
        fetchRoom();
    };

    if (isLoading) {
        return (
            <AppLayout>
                <div className="flex items-center justify-center py-24 text-[var(--hms-text-muted)]">
                    <RefreshCcw className="mr-2 h-4 w-4 animate-spin" strokeWidth={1.8} />
                    Chargement de la chambre...
                </div>
            </AppLayout>
        );
    }

    if (error || !room) {
        return (
            <AppLayout>
                <HmsCard>
                    <div className="flex items-start gap-4">
                        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" strokeWidth={1.8} />
                        <div>
                            <p className="font-semibold text-red-700">Chambre introuvable</p>
                            <p className="mt-1 text-sm text-red-600">{error}</p>
                        </div>
                    </div>
                </HmsCard>
            </AppLayout>
        );
    }

    const tiles = [
        { icon: Hash, label: "Numéro", value: room.number },
        { icon: BedDouble, label: "Type", value: TYPE_LABELS[room.type] ?? room.type },
        { icon: Building2, label: "Étage", value: `Étage ${room.floor}` },
        { icon: Users, label: "Capacité", value: `${room.capacity} personne${room.capacity > 1 ? "s" : ""}` },
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
                        <Link href={`/rooms/${id}/edit`}>
                            <HmsButton>
                                <Pencil className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                Modifier
                            </HmsButton>
                        </Link>
                        <HmsButton variant="danger" onClick={() => setConfirmDelete(true)}>
                            <Power className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                            Désactiver
                        </HmsButton>
                    </>
                }
            />

            <HmsCard>
                <div className="flex items-center justify-between">
                    <RoomStatusBadge status={room.status} />
                    <span
                        className={
                            room.active
                                ? "inline-flex items-center rounded-full bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-700 ring-1 ring-inset ring-emerald-200"
                                : "inline-flex items-center rounded-full bg-red-50 px-3 py-1 text-xs font-semibold text-red-700 ring-1 ring-inset ring-red-200"
                        }
                    >
                        {room.active ? "Active" : "Inactive"}
                    </span>
                </div>

                {room.description && (
                    <p className="mt-5 text-base text-[var(--hms-text-muted)]">{room.description}</p>
                )}

                <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
                    {tiles.map(({ icon: Icon, label, value }) => (
                        <div key={label} className="rounded-2xl bg-slate-50 p-5 ring-1 ring-inset ring-[var(--hms-soft-border)]">
                            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white text-[var(--hms-text-muted)] shadow-sm">
                                <Icon className="h-[18px] w-[18px]" strokeWidth={1.8} />
                            </div>
                            <p className="mt-4 text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">{label}</p>
                            <p className="mt-1 text-lg font-bold text-[var(--hms-text)]">{value}</p>
                        </div>
                    ))}
                </div>
            </HmsCard>

            <HmsCard className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
                <div>
                    <p className="text-sm font-medium text-[var(--hms-text-muted)]">Prix par nuit</p>
                    <p className="mt-1 text-4xl font-bold text-[var(--hms-text)]">{room.pricePerNight} DH</p>
                </div>

                <div className="flex flex-wrap gap-3">
                    <HmsButton variant="secondary" onClick={() => setStatusDialogOpen(true)}>
                        <Repeat className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                        Changer statut
                    </HmsButton>
                    <Link href={`/reservations?roomId=${id}`}>
                        <HmsButton variant="secondary">
                            <History className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                            Historique
                        </HmsButton>
                    </Link>
                    <Link href={`/reservations/create?roomId=${id}`}>
                        <HmsButton>
                            <CalendarPlus className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                            Réserver
                        </HmsButton>
                    </Link>
                </div>
            </HmsCard>

            <DeleteRoomDialog
                isOpen={confirmDelete}
                onClose={() => setConfirmDelete(false)}
                onConfirm={handleDeactivate}
                roomNumber={room.number}
                isLoading={isDeleting}
            />

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
