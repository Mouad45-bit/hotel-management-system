"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import type { Client } from "@/types/client";
import { ClientService, type ClientFilters as FilterTypes } from "@/services/client.service";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { Plus, RefreshCw, AlertCircle } from "lucide-react";

import { ClientFilters } from "@/components/clients/ClientFilters";
import { ClientStatsCards } from "@/components/clients/ClientStatsCards";
import { ClientTable } from "@/components/clients/ClientTable";
import { DeactivateClientDialog } from "@/components/clients/DeactivateClientDialog";
import { ActivateClientDialog } from "@/components/clients/ActivateClientDialog";

const PAGE_SIZE = 10;

export default function ClientsPage() {
    const [clients, setClients] = useState<Client[]>([]);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filters, setFilters] = useState<FilterTypes>({});
    const [showInactive, setShowInactive] = useState(false);
    const [currentPage, setCurrentPage] = useState(0);

    const [clientToDeactivate, setClientToDeactivate] = useState<Client | null>(null);
    const [isDeactivating, setIsDeactivating] = useState(false);

    const [clientToActivate, setClientToActivate] = useState<Client | null>(null);
    const [isActivating, setIsActivating] = useState(false);

    const loadData = useCallback(async (activeFilters: FilterTypes, isInactive: boolean) => {
        setLoading(true);
        setError(null);
        try {
            const data = isInactive
                ? await ClientService.getInactiveClients()
                : await ClientService.getClients(activeFilters);
            setClients(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Erreur de connexion au serveur");
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        const timeoutId = window.setTimeout(() => {
            void loadData({}, false);
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, [loadData]);

    const applyFilter = (key: keyof FilterTypes, value: string) => {
        const updated = { ...filters, [key]: value || undefined };
        setFilters(updated);
        setCurrentPage(0);
        void loadData(updated, showInactive);
    };

    const handleInactiveToggle = () => {
        const nextShowInactive = !showInactive;
        setShowInactive(nextShowInactive);
        setCurrentPage(0);
        void loadData(filters, nextShowInactive);
    };

    const totalPages = Math.max(1, Math.ceil(clients.length / PAGE_SIZE));
    const paginatedClients = clients.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);

    const handleDeactivateConfirm = async () => {
        if (!clientToDeactivate) return;
        setIsDeactivating(true);
        try {
            await ClientService.deleteClient(clientToDeactivate.id);
            setClientToDeactivate(null);
            void loadData(filters, showInactive);
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur lors de la désactivation");
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
            alert(err instanceof Error ? err.message : "Erreur lors de la réactivation");
            setClientToActivate(null);
        } finally {
            setIsActivating(false);
        }
    };

    return (
        <AppLayout>
            <PageHeader
                title="Clients"
                description="Suivez les fiches clients et leurs informations de contact."
                actions={
                    <>
                        <HmsButton
                            variant="secondary"
                            onClick={handleInactiveToggle}
                            className={showInactive ? "border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100" : undefined}
                        >
                            {showInactive ? "Retour aux actifs" : "Clients désactivés"}
                        </HmsButton>
                        <Link href="/clients/create">
                            <HmsButton>
                                <Plus className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                Nouveau client
                            </HmsButton>
                        </Link>
                    </>
                }
            />

            <div className="space-y-6">
                {!error && !showInactive && <ClientStatsCards clients={clients} loading={isLoading} />}

                {error ? (
                    <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                        <div>
                            <p className="font-semibold">Erreur de chargement</p>
                            <p className="mt-1">{error}</p>
                            <button
                                type="button"
                                onClick={() => void loadData(filters, showInactive)}
                                className="mt-3 cursor-pointer text-sm font-semibold text-red-700 underline transition hover:text-red-900"
                            >
                                Réessayer
                            </button>
                        </div>
                    </div>
                ) : (
                    <HmsCard className="overflow-hidden p-0">
                        <div className="flex flex-col gap-2 border-b border-[var(--hms-soft-border)] px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between">
                            <p className="text-sm font-semibold text-[var(--hms-text-muted)]">
                                {isLoading && clients.length === 0
                                    ? "Chargement des clients"
                                    : `${clients.length} client${clients.length > 1 ? "s" : ""} trouvé${clients.length > 1 ? "s" : ""}`}
                            </p>

                            <div className="flex items-center gap-1.5">
                                <HmsButton
                                    type="button"
                                    variant="secondary"
                                    onClick={() => void loadData(filters, showInactive)}
                                    disabled={isLoading}
                                >
                                    <RefreshCw aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                    Actualiser
                                </HmsButton>

                                <ClientFilters
                                    filters={filters}
                                    onFilterChange={applyFilter}
                                />
                            </div>
                        </div>

                        <ClientTable
                            clients={paginatedClients}
                            loading={isLoading}
                            emptyMessage="Aucun client ne correspond aux filtres."
                            onDeactivateClick={setClientToDeactivate}
                            onActivateClick={setClientToActivate}
                        />

                        <div className="flex items-center justify-between border-t border-[var(--hms-soft-border)] px-6 py-5">
                            <p className="text-sm text-[var(--hms-text-muted)]">
                                Page <span className="font-medium text-[var(--hms-text)]">{currentPage + 1}</span> sur <span className="font-medium text-[var(--hms-text)]">{totalPages}</span>
                            </p>
                            <div className="flex items-center gap-2">
                                <HmsButton type="button" variant="secondary" onClick={() => setCurrentPage((p) => p - 1)} disabled={isLoading || currentPage === 0} className="min-h-10 px-3">
                                    Précédent
                                </HmsButton>
                                <HmsButton type="button" variant="secondary" onClick={() => setCurrentPage((p) => p + 1)} disabled={isLoading || currentPage >= totalPages - 1} className="min-h-10 px-3">
                                    Suivant
                                </HmsButton>
                            </div>
                        </div>
                    </HmsCard>
                )}
            </div>

            <DeactivateClientDialog
                isOpen={clientToDeactivate !== null}
                onClose={() => setClientToDeactivate(null)}
                onConfirm={handleDeactivateConfirm}
                clientName={clientToDeactivate ? `${clientToDeactivate.firstName} ${clientToDeactivate.lastName}` : ""}
                isLoading={isDeactivating}
            />

            <ActivateClientDialog
                isOpen={clientToActivate !== null}
                onClose={() => setClientToActivate(null)}
                onConfirm={handleActivateConfirm}
                clientName={clientToActivate ? `${clientToActivate.firstName} ${clientToActivate.lastName}` : ""}
                isLoading={isActivating}
            />
        </AppLayout>
    );
}
