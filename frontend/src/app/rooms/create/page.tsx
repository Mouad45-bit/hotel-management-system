'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { RoomForm } from '@/components/rooms/RoomForm';
import { RoomService } from '@/services/room.service';
import { RoomFormValues } from '@/schemas/room.schema';

export default function CreateRoomPage() {
    const router = useRouter();
    const [isSubmitting, setIsSubmitting] = useState(false);

    const handleSubmit = async (data: RoomFormValues) => {
        setIsSubmitting(true);
        try {
            await RoomService.createRoom(data);
            router.push('/rooms');
            router.refresh();
        } catch (error) {
            setIsSubmitting(false);
            throw error;
        }
    };

    const handleCancel = () => {
        router.push('/rooms');
    };

    return (
        <AppLayout>
            <PageHeader
                backHref="/rooms"
                eyebrow="Création"
                title="Nouvelle chambre"
                description="Ajoutez une chambre à l'inventaire de l'hôtel, définissez ses informations permanentes et son activation administrative."
            />

            <RoomForm
                onSubmit={handleSubmit}
                onCancel={handleCancel}
                isLoading={isSubmitting}
                submitLabel="Créer"
            />
        </AppLayout>
    );
}
