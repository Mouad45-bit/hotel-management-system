'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { ReservationForm } from '@/components/reservations/ReservationForm';
import { ReservationService } from '@/services/reservation.service';
import { Reservation } from '@/types/reservation';
import { ReservationFormValues } from '@/schemas/reservation.schema';
import { RefreshCcw, AlertCircle } from 'lucide-react';

export default function EditReservationPage() {
    const router = useRouter();
    const params = useParams<{ id: string }>();
    const id = Number(params.id);

    const [reservation, setReservation] = useState<Reservation | null>(null);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [isSubmitting, setIsSubmitting] = useState(false);

    useEffect(() => {
        ReservationService.getReservationById(id)
            .then(setReservation)
            .catch((err) => setError(err instanceof Error ? err.message : 'Réservation introuvable'))
            .finally(() => setLoading(false));
    }, [id]);

    const handleSubmit = async (data: ReservationFormValues) => {
        setIsSubmitting(true);
        try {
            await ReservationService.updateReservation(id, {
                checkInDate: data.checkInDate,
                checkOutDate: data.checkOutDate,
                notes: data.notes,
            });
            router.push(`/reservations/${id}`);
            router.refresh();
        } catch (error) {
            setIsSubmitting(false);
            throw error;
        }
    };

    const handleCancel = () => {
        router.push(`/reservations/${id}`);
    };

    if (isLoading) {
        return (
            <AppLayout>
                <div className="flex items-center justify-center py-24 text-zinc-400">
                    <RefreshCcw size={18} className="mr-2 animate-spin" />
                    Chargement...
                </div>
            </AppLayout>
        );
    }

    if (error || !reservation) {
        return (
            <AppLayout>
                <div className="flex items-start gap-4 rounded-2xl border border-red-200 bg-red-50 p-6">
                    <AlertCircle className="mt-0.5 shrink-0 text-red-500" size={20} />
                    <div>
                        <p className="font-semibold text-red-700">Réservation introuvable</p>
                        <p className="mt-1 text-sm text-red-600">{error}</p>
                    </div>
                </div>
            </AppLayout>
        );
    }

    return (
        <AppLayout>
            <PageHeader
                backHref={`/reservations/${id}`}
                eyebrow={`RES-${reservation.id}`}
                title="Modifier la réservation"
                description="Modifiez les dates et les notes. Le prix total sera recalculé automatiquement."
            />

            <ReservationForm
                initialData={{
                    roomId: reservation.roomId,
                    clientId: reservation.clientId,
                    checkInDate: reservation.checkInDate,
                    checkOutDate: reservation.checkOutDate,
                    notes: reservation.notes ?? '',
                }}
                onSubmit={handleSubmit}
                onCancel={handleCancel}
                isLoading={isSubmitting}
                submitLabel="Enregistrer"
                lockRoomAndClient
            />
        </AppLayout>
    );
}
