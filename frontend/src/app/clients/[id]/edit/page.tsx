'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { ClientForm } from '@/components/clients/ClientForm';
import { ClientService } from '@/services/client.service';
import { Client } from '@/types/client';
import { ClientFormValues } from '@/schemas/client.schema';
import { RefreshCcw, AlertCircle } from 'lucide-react';

export default function EditClientPage() {
    const router = useRouter();
    const params = useParams<{ id: string }>();
    const id = Number(params.id);

    const [client, setClient] = useState<Client | null>(null);
    const [isLoading, setLoading] = useState(true);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        ClientService.getClientById(id)
            .then(setClient)
            .catch((err) => setError(err instanceof Error ? err.message : 'Client introuvable'))
            .finally(() => setLoading(false));
    }, [id]);

    const handleSubmit = async (data: ClientFormValues) => {
        setIsSubmitting(true);
        try {
            await ClientService.updateClient(id, data);
            router.push(`/clients/${id}`);
            router.refresh();
        } catch (error) {
            setIsSubmitting(false);
            throw error;
        }
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

    if (error || !client) {
        return (
            <AppLayout>
                <div className="flex items-start gap-4 rounded-2xl border border-red-200 bg-red-50 p-6">
                    <AlertCircle className="mt-0.5 shrink-0 text-red-500" size={20} />
                    <p className="font-semibold text-red-700">Client introuvable</p>
                </div>
            </AppLayout>
        );
    }

    return (
        <AppLayout>
            <PageHeader
                backHref={`/clients/${id}`}
                eyebrow={`CLIENT-${client.id}`}
                title={`Modifier ${client.firstName} ${client.lastName}`}
                description="Mettez à jour les informations du client."
            />
            <ClientForm
                initialData={{
                    firstName: client.firstName,
                    lastName: client.lastName,
                    email: client.email ?? '',
                    phone: client.phone ?? '',
                    cin: client.cin ?? '',
                    passportNumber: client.passportNumber ?? '',
                    nationality: client.nationality ?? '',
                    address: client.address ?? '',
                    birthDate: client.birthDate ?? '',
                }}
                onSubmit={handleSubmit}
                onCancel={() => router.push(`/clients/${id}`)}
                isLoading={isSubmitting}
                submitLabel="Enregistrer"
            />
        </AppLayout>
    );
}
