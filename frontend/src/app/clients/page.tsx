'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Client } from '@/types/client';
import { ClientService, ClientFilters as FilterTypes } from '@/services/client.service';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { Plus, RefreshCcw, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

import { ClientFilters } from '@/components/clients/ClientFilters';
import { ClientTable } from '@/components/clients/ClientTable';
import { DeactivateClientDialog } from '@/components/clients/DeactivateClientDialog';
import { ActivateClientDialog } from '@/components/clients/ActivateClientDialog';

export default function ClientsPage() {
    const [clients, setClients] = useState<Client[]>([]);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filters, setFilters] = useState<FilterTypes>({});
    const [showInactive, setShowInactive] = useState(false);

    const [clientToDeactivate, setClientToDeactivate] = useState<Client | null>(null);
    const [isDeactivating, setIsDeactivating] = useState(false);

    const [clientToActivate, setClientToActivate] = useState<Client | null>(null);
    const [isActivating, setIsActivating] = useState(false);

    const loadData = async (activeFilters: FilterTypes = filters, isInactive: boolean = showInactive) => {
        setLoading(true);
        setError(null);
        try {
            const data = isInactive
                ? await ClientService.getInactiveClients()
                : await ClientService.getClients(activeFilters);
            setClients(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Erreur de connexion au serveur');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        void loadData();
    }, []);

    useEffect(() => {
        void loadData(filters, showInactive);
    }, [showInactive]);

    const applyFilter = (key: keyof FilterTypes, value: string) => {
        const updated = { ...filters, [key]: value || undefined };
        setFilters(updated);
        void loadData(updated, showInactive);
    };

    const resetFilters = () => {
        setFilters({});
        void loadData({}, showInactive);
    };

    const handleDeactivateConfirm = async () => {
        if (!clientToDeactivate) return;
        setIsDeactivating(true);
        try {
            await ClientService.deleteClient(clientToDeactivate.id);
            setClientToDeactivate(null);
            void loadData(filters, showInactive);
        } catch (err) {
            alert(err instanceof Error ? err.message : 'Erreur lors de la désactivation');
            setClientToDeactivate(null);
        } finally {
            setIsDeactivating(false);
        }
    };

    const handleActivateConfirm = async () => {
        if (!clientToActivate) return;
        setIsActivating(true);
        try {
            await ClientService.activateClient(clientToActivate.id);
            setClientToActivate(null);
            void loadData(filters, showInactive);
        } catch (err) {
            alert(err instanceof Error ? err.message : 'Erreur lors de la réactivation');
            setClientToActivate(null);
        } finally {
            setIsActivating(false);
        }
    };

    return (
        <AppLayout>
            <PageHeader
                title="Gestion des clients"
                description="Créez et gérez les fiches clients de l'hôtel. Chaque client peut être lié à des réservations et des factures."
                actions={
                    <>
                        <button
                            onClick={() => setShowInactive(!showInactive)}
                            className={cn(
                                'rounded-2xl border px-4 py-2.5 text-sm font-semibold transition',
                                showInactive
                                    ? 'border-zinc-900 bg-zinc-900 text-white'
                                    : 'border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50'
                            )}
                        >
                            {showInactive ? 'Retour aux actifs' : 'Clients désactivés'}
                        </button>
                        <Link
                            href="/clients/create"
                            className="inline-flex items-center gap-2 rounded-2xl bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-zinc-800"
                        >
                            <Plus size={18} />
                            Nouveau client
                        </Link>
                    </>
                }
            />

            <div className="space-y-6">
                <ClientFilters
                    filters={filters}
                    onFilterChange={applyFilter}
                    onReset={resetFilters}
                    count={clients.length}
                />

                {error ? (
                    <div className="flex items-start gap-4 rounded-2xl border border-red-200 bg-red-50 p-6">
                        <AlertCircle className="mt-0.5 shrink-0 text-red-500" size={20} />
                        <div>
                            <p className="font-semibold text-red-700">Impossible de contacter le serveur</p>
                            <p className="mt-1 text-sm text-red-600">{error}</p>
                            <button
                                onClick={() => void loadData(filters, showInactive)}
                                className="mt-3 text-sm font-medium text-red-700 underline transition hover:text-red-900"
                            >
                                Réessayer
                            </button>
                        </div>
                    </div>
                ) : isLoading && clients.length === 0 ? (
                    <div className="flex items-center justify-center py-24 text-zinc-400 bg-white rounded-2xl ring-1 ring-zinc-200">
                        <RefreshCcw size={18} className="mr-2 animate-spin" />
                        Chargement des clients...
                    </div>
                ) : (
                    <div className={cn('transition-opacity duration-200', isLoading && 'opacity-50 pointer-events-none')}>
                        <ClientTable
                            clients={clients}
                            onDeactivateClick={setClientToDeactivate}
                            onActivateClick={setClientToActivate}
                        />
                    </div>
                )}
            </div>

            <DeactivateClientDialog
                isOpen={clientToDeactivate !== null}
                onClose={() => setClientToDeactivate(null)}
                onConfirm={handleDeactivateConfirm}
                clientName={clientToDeactivate ? `${clientToDeactivate.firstName} ${clientToDeactivate.lastName}` : ''}
                isLoading={isDeactivating}
            />

            <ActivateClientDialog
                isOpen={clientToActivate !== null}
                onClose={() => setClientToActivate(null)}
                onConfirm={handleActivateConfirm}
                clientName={clientToActivate ? `${clientToActivate.firstName} ${clientToActivate.lastName}` : ''}
                isLoading={isActivating}
            />
        </AppLayout>
    );
}
