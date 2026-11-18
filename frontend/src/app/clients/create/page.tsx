'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { ClientForm } from '@/components/clients/ClientForm';
import { ClientService } from '@/services/client.service';
import { ClientFormValues } from '@/schemas/client.schema';

export default function CreateClientPage() {
    const router = useRouter();
    const [isSubmitting, setIsSubmitting] = useState(false);

    const handleSubmit = async (data: ClientFormValues) => {
        setIsSubmitting(true);
        try {
            await ClientService.createClient(data);
            router.push('/clients');
            router.refresh();
        } catch (error) {
            setIsSubmitting(false);
            throw error;
        }
    };

    return (
        <AppLayout>
            <PageHeader
                backHref="/clients"
                eyebrow="Création"
                title="Nouveau client"
                description="Enregistrez un nouveau client dans le système. Au moins un moyen d'identification est requis."
            />
            <ClientForm
                onSubmit={handleSubmit}
                onCancel={() => router.push('/clients')}
                isLoading={isSubmitting}
                submitLabel="Créer"
            />
        </AppLayout>
    );
}
