"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { Client } from "@/types/client";
import { ClientService, type ClientFilters as FilterTypes } from "@/services/client.service";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { Plus, RefreshCcw, AlertCircle } from "lucide-react";
import { cn } from "@/lib/utils";

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

    const loadData = async (activeFilters: FilterTypes = filters, isInactive: boolean = showInactive) => {
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
        setCurrentPage(0);
        void loadData(updated, showInactive);
    };

    const resetFilters = () => {
        setFilters({});
        setCurrentPage(0);
        void loadData({}, showInactive);
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
                title="Gestion des clients"
                description="Créez et gérez les fiches clients de l'hôtel. Chaque client peut être lié à des réservations et des factures."
                actions={
                    <>
                        <HmsButton
                            variant={showInactive ? "primary" : "secondary"}
                            onClick={() => setShowInactive(!showInactive)}
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
                {!error && clients.length > 0 && !showInactive && (
                    <ClientStatsCards clients={clients} showInactive={showInactive} />
                )}

                <ClientFilters
                    filters={filters}
                    onFilterChange={applyFilter}
                    onReset={resetFilters}
                    count={clients.length}
                />

                {error ? (
                    <HmsCard>
                        <div className="flex items-start gap-4">
                            <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" strokeWidth={1.8} />
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
                    </HmsCard>
                ) : isLoading && clients.length === 0 ? (
                    <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                            {Array.from({ length: 3 }).map((_, i) => (
                                <HmsCard key={i} className="h-20 animate-pulse bg-slate-50">{null}</HmsCard>
                            ))}
                        </div>
                        <HmsCard className="overflow-hidden p-0">
                            <div className="divide-y divide-[var(--hms-soft-border)]">
                                {Array.from({ length: 5 }).map((_, i) => (
                                    <div key={i} className="flex items-center gap-4 px-6 py-4">
                                        <div className="h-4 w-24 animate-pulse rounded bg-slate-100" />
                                        <div className="h-4 w-32 animate-pulse rounded bg-slate-100" />
                                        <div className="h-4 w-20 animate-pulse rounded bg-slate-100" />
                                        <div className="ml-auto h-4 w-16 animate-pulse rounded bg-slate-100" />
                                    </div>
                                ))}
                            </div>
                        </HmsCard>
                    </div>
                ) : (
                    <div className={cn("transition-opacity duration-200", isLoading && "pointer-events-none opacity-50")}>
                        <HmsCard className="p-0 overflow-hidden">
                            <ClientTable
                                clients={paginatedClients}
                                onDeactivateClick={setClientToDeactivate}
                                onActivateClick={setClientToActivate}
                            />

                            {clients.length > PAGE_SIZE && (
                                <div className="flex items-center justify-between border-t border-[var(--hms-soft-border)] px-6 py-5">
                                    <p className="text-sm text-[var(--hms-text-muted)]">
                                        Page <span className="font-medium text-[var(--hms-text)]">{currentPage + 1}</span> sur <span className="font-medium text-[var(--hms-text)]">{totalPages}</span>
                                    </p>
                                    <div className="flex items-center gap-2">
                                        <HmsButton variant="secondary" onClick={() => setCurrentPage((p) => p - 1)} disabled={currentPage === 0} className="min-h-10 px-3">
                                            Précédent
                                        </HmsButton>
                                        <HmsButton variant="secondary" onClick={() => setCurrentPage((p) => p + 1)} disabled={currentPage >= totalPages - 1} className="min-h-10 px-3">
                                            Suivant
                                        </HmsButton>
                                    </div>
                                </div>
                            )}
                        </HmsCard>
                    </div>
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
