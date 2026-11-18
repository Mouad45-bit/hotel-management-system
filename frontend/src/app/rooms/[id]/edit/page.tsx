"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsCard } from "@/components/hms/HmsCard";
import { RoomForm } from "@/components/rooms/RoomForm";
import { RoomService } from "@/services/room.service";
import type { RoomFormValues } from "@/schemas/room.schema";
import type { Room } from "@/types/room";
import { RefreshCcw, AlertCircle } from "lucide-react";

export default function EditRoomPage() {
    const router = useRouter();
    const params = useParams<{ id: string }>();
    const id = Number(params.id);

    const [room, setRoom] = useState<Room | null>(null);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [isSubmitting, setIsSubmitting] = useState(false);

    useEffect(() => {
        let cancelled = false;
        RoomService.getRoomById(id)
            .then((data) => { if (!cancelled) setRoom(data); })
            .catch((err) => {
                if (!cancelled) setError(err instanceof Error ? err.message : "Chambre introuvable");
            })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [id]);

    const handleSubmit = async (data: RoomFormValues) => {
        setIsSubmitting(true);
        try {
            await RoomService.updateRoom(id, data);
            router.push(`/rooms/${id}`);
            router.refresh();
        } catch (err) {
            setIsSubmitting(false);
            throw err;
        }
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

    return (
        <AppLayout>
            <PageHeader
                backHref={`/rooms/${id}`}
                eyebrow={`CH-${room.number}`}
                title={`Modifier chambre ${room.number}`}
                description="Modifiez les informations permanentes de la chambre."
            />
            <RoomForm
                initialData={{
                    number: room.number,
                    floor: room.floor,
                    type: room.type,
                    pricePerNight: room.pricePerNight,
                    capacity: room.capacity,
                    active: room.active,
                    status: room.status,
                    description: room.description ?? "",
                }}
                onSubmit={handleSubmit}
                onCancel={() => router.push(`/rooms/${id}`)}
                isLoading={isSubmitting}
                submitLabel="Enregistrer"
            />
        </AppLayout>
    );
}
