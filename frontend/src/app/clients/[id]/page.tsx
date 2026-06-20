'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { ClientStatusBadge } from '@/components/clients/ClientStatusBadge';
import { DeactivateClientDialog } from '@/components/clients/DeactivateClientDialog';
import { ClientService } from '@/services/client.service';
import { Client } from '@/types/client';
import {
    AlertCircle,
    CalendarDays,
    FileText,
    Mail,
    MapPin,
    Pencil,
    Phone,
    Power,
    RefreshCcw,
    Shield,
    User,
} from 'lucide-react';

export default function ClientDetailPage() {
    const router = useRouter();
    const params = useParams<{ id: string }>();
    const id = Number(params.id);

    const [client, setClient] = useState<Client | null>(null);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [confirmDeactivate, setConfirmDeactivate] = useState(false);
    const [isDeactivating, setIsDeactivating] = useState(false);

    const fetchClient = () => {
        setLoading(true);
        ClientService.getClientById(id)
            .then(setClient)
            .catch((err) => setError(err instanceof Error ? err.message : 'Client introuvable'))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        fetchClient();
    }, [id]);

    const handleDeactivate = async () => {
        setIsDeactivating(true);
        try {
            await ClientService.deleteClient(id);
            router.push('/clients');
            router.refresh();
        } catch (err) {
            alert(err instanceof Error ? err.message : 'Erreur lors de la désactivation');
            setConfirmDeactivate(false);
        } finally {
            setIsDeactivating(false);
        }
    };

    if (isLoading) {
        return (
            <AppLayout>
                <div className="flex items-center justify-center py-24 text-zinc-400">
                    <RefreshCcw size={18} className="mr-2 animate-spin" />
                    Chargement du client...
                </div>
            </AppLayout>
        );
    }

    if (error || !client) {
        return (
            <AppLayout>
                <div className="flex items-start gap-4 rounded-2xl border border-red-200 bg-red-50 p-6">
                    <AlertCircle className="mt-0.5 shrink-0 text-red-500" size={20} />
                    <div>
                        <p className="font-semibold text-red-700">Client introuvable</p>
                        <p className="mt-1 text-sm text-red-600">{error}</p>
                    </div>
                </div>
            </AppLayout>
        );
    }

    const tiles = [
        { icon: Mail, label: 'Email', value: client.email ?? '—' },
        { icon: Phone, label: 'Téléphone', value: client.phone ?? '—' },
        { icon: Shield, label: 'CIN', value: client.cin ?? '—' },
        { icon: User, label: 'Passeport', value: client.passportNumber ?? '—' },
    ];

    return (
        <AppLayout>
            <PageHeader
                backHref="/clients"
                eyebrow={`CLIENT-${client.id}`}
                title={`${client.firstName} ${client.lastName}`}
                description="Fiche client : informations personnelles, moyens d'identification et accès aux actions principales."
                actions={
                    <>
                        <Link
                            href={`/clients/${id}/edit`}
                            className="inline-flex items-center gap-2 rounded-2xl bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-zinc-800"
                        >
                            <Pencil size={16} />
                            Modifier
                        </Link>
                        <button
                            onClick={() => setConfirmDeactivate(true)}
                            className="inline-flex items-center gap-2 rounded-2xl bg-orange-500 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-orange-600"
                        >
                            <Power size={16} />
                            Désactiver
                        </button>
                    </>
                }
            />

            {/* Carte infos générales */}
            <div className="rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
                <div className="flex items-center justify-between">
                    <ClientStatusBadge active={client.active} />
                    {client.nationality && (
                        <span className="inline-flex items-center rounded-full bg-zinc-50 px-3 py-1 text-xs font-medium text-zinc-700 ring-1 ring-inset ring-zinc-200">
                            {client.nationality}
                        </span>
                    )}
                </div>

                <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
                    {tiles.map(({ icon: Icon, label, value }) => (
                        <div key={label} className="rounded-2xl border border-zinc-100 bg-zinc-50 p-5">
                            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white text-zinc-500 shadow-sm">
                                <Icon size={18} />
                            </div>
                            <p className="mt-4 text-xs font-semibold uppercase tracking-wider text-zinc-400">{label}</p>
                            <p className="mt-1 text-sm font-bold text-zinc-900 break-all">{value}</p>
                        </div>
                    ))}
                </div>

                {(client.address || client.birthDate) && (
                    <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2">
                        {client.birthDate && (
                            <div className="flex items-center gap-3 rounded-xl bg-zinc-50 p-4">
                                <CalendarDays size={18} className="text-zinc-400" />
                                <div>
                                    <p className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Date de naissance</p>
                                    <p className="mt-0.5 text-sm font-medium text-zinc-900">{client.birthDate}</p>
                                </div>
                            </div>
                        )}
                        {client.address && (
                            <div className="flex items-center gap-3 rounded-xl bg-zinc-50 p-4">
                                <MapPin size={18} className="text-zinc-400" />
                                <div>
                                    <p className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Adresse</p>
                                    <p className="mt-0.5 text-sm font-medium text-zinc-900">{client.address}</p>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* Actions rapides */}
            <div className="flex flex-col gap-6 rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200 lg:flex-row lg:items-center lg:justify-between">
                <div>
                    <p className="text-sm font-medium text-zinc-500">Client enregistré le</p>
                    <p className="mt-1 text-lg font-bold text-zinc-950">
                        {client.createdAt ? new Date(client.createdAt).toLocaleDateString('fr-FR') : '—'}
                    </p>
                </div>
                <div className="flex flex-wrap gap-3">
                    <button className="inline-flex items-center gap-2 rounded-2xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50">
                        <FileText size={16} />
                        Factures
                    </button>
                    <button className="inline-flex items-center gap-2 rounded-2xl bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-zinc-800">
                        <CalendarDays size={16} />
                        Réservations
                    </button>
                </div>
            </div>

            <DeactivateClientDialog
                isOpen={confirmDeactivate}
                onClose={() => setConfirmDeactivate(false)}
                onConfirm={handleDeactivate}
                clientName={`${client.firstName} ${client.lastName}`}
                isLoading={isDeactivating}
            />
        </AppLayout>
    );
}
