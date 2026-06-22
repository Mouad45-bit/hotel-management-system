'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { ReservationForm } from '@/components/reservations/ReservationForm';
import { ReservationService } from '@/services/reservation.service';
import { ReservationFormValues } from '@/schemas/reservation.schema';

export default function CreateReservationPage() {
    const router = useRouter();
    const [isSubmitting, setIsSubmitting] = useState(false);

    const handleSubmit = async (data: ReservationFormValues) => {
        setIsSubmitting(true);
        try {
            await ReservationService.createReservation(data);
            router.push('/reservations');
            router.refresh();
        } catch (error) {
            setIsSubmitting(false);
            throw error;
        }
    };

    const handleCancel = () => {
        router.push('/reservations');
    };

    return (
        <AppLayout>
            <PageHeader
                backHref="/reservations"
                eyebrow="Création"
                title="Nouvelle réservation"
                description="Sélectionnez un client et une chambre disponible, définissez les dates de séjour et le prix sera calculé automatiquement."
            />

            <ReservationForm
                onSubmit={handleSubmit}
                onCancel={handleCancel}
                isLoading={isSubmitting}
                submitLabel="Créer la réservation"
            />
        </AppLayout>
    );
}
