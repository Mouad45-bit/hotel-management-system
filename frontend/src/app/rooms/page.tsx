'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Room, RoomStats } from '@/types/room';
import { RoomService, RoomFilters as FilterTypes } from '@/services/room.service';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { Plus, RefreshCcw, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

import { RoomFilters } from '@/components/rooms/RoomFilters';
import { RoomTable } from '@/components/rooms/RoomTable';
import { DeleteRoomDialog } from '@/components/rooms/DeleteRoomDialog';
import { RoomStatsCards } from '@/components/rooms/RoomStatsCards';
import { ActivateRoomDialog } from '@/components/rooms/ActivateRoomDialog';

export default function RoomsPage() {
    const [rooms, setRooms] = useState<Room[]>([]);
    const [stats, setStats] = useState<RoomStats | null>(null);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filters, setFilters] = useState<FilterTypes>({});
    const [showInactive, setShowInactive] = useState(false);

    const [roomToDelete, setRoomToDelete] = useState<Room | null>(null);
    const [isDeleting, setIsDeleting] = useState(false);

    const [roomToActivate, setRoomToActivate] = useState<Room | null>(null);
    const [isActivating, setIsActivating] = useState(false);

    const loadData = async (activeFilters: FilterTypes = filters, isInactive: boolean = showInactive) => {
        setLoading(true);
        setError(null);
        try {
            // Requêtes en parallèle au backend
            const [roomsData, statsData] = await Promise.all([
                isInactive ? RoomService.getDisabledRooms() : RoomService.getRooms(activeFilters),
                RoomService.getStats()
            ]);

            // Astuce : Le endpoint backend "/disabled" ne prend pas de filtres,
            // donc on applique le filtre "numéro" côté frontend pour le mode inactif !
            let finalRooms = roomsData;
            if (isInactive && activeFilters.number) {
                finalRooms = finalRooms.filter(r => r.number.includes(activeFilters.number!));
            }

            setRooms(finalRooms);
            setStats(statsData);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Erreur de connexion au serveur');
        } finally {
            setLoading(false);
        }
    };

    // Chargement initial
    useEffect(() => {
        void loadData();
    }, []);

    // Se déclenche quand on clique sur le bouton "Chambres désactivées"
    useEffect(() => {
        void loadData(filters, showInactive);
    }, [showInactive]);

    const applyFilter = (key: keyof FilterTypes, value: string) => {
        const updated = { ...filters, [key]: value || undefined };
        setFilters(updated);
        // Exécute la recherche sans bloquer la saisie
        void loadData(updated, showInactive);
    };

    const resetFilters = () => {
        setFilters({});
        void loadData({}, showInactive);
    };

    const handleDeleteConfirm = async () => {
        if (!roomToDelete) return;
        setIsDeleting(true);
        try {
            await RoomService.deleteRoom(roomToDelete.id);
            setRoomToDelete(null);
            void loadData(filters, showInactive);
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur lors de la suppression");
            setRoomToDelete(null);
        } finally {
            setIsDeleting(false);
        }
    };

    const handleActivateConfirm = async () => {
        if (!roomToActivate) return;
        setIsActivating(true);
        try {
            await RoomService.activateRoom(roomToActivate.id);
            setRoomToActivate(null);
            void loadData(filters, showInactive);
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur lors de la réactivation");
            setRoomToActivate(null);
        } finally {
            setIsActivating(false);
        }
    };

    const header = (
        <PageHeader
            title="Gestion des chambres"
            description="Créez, suivez et pilotez l'inventaire des chambres. Cette interface affiche les chambres avec recherche, filtrage, statut métier et activation administrative."
            actions={
                <>
                    <button
                        onClick={() => setShowInactive(!showInactive)}
                        className={cn(
                            "rounded-2xl border px-4 py-2.5 text-sm font-semibold transition",
                            showInactive
                                ? "border-zinc-900 bg-zinc-900 text-white"
                                : "border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50"
                        )}
                    >
                        {showInactive ? "Retour aux actives" : "Chambres désactivées"}
                    </button>
                    <Link
                        href="/rooms/create"
                        className="inline-flex items-center gap-2 rounded-2xl bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-zinc-800"
                    >
                        <Plus size={18} />
                        Nouvelle chambre
                    </Link>
                </>
            }
        />
    );

    return (
        <AppLayout>
            {header}

            <div className="space-y-6">
                {/* On cache les stats globales quand on fouille dans les archives */}
                {!error && stats && !showInactive && <RoomStatsCards stats={stats} />}

                {/* Les filtres restent TOUJOURS montés pour ne jamais perdre le focus clavier */}
                <RoomFilters
                    filters={filters}
                    onFilterChange={applyFilter}
                    onReset={resetFilters}
                    count={rooms.length}
                />

                {/* Zone de contenu conditionnelle */}
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
                ) : isLoading && rooms.length === 0 ? (
                    // Spinner complet uniquement si c'est le TOUT PREMIER chargement (0 chambre)
                    <div className="flex items-center justify-center py-24 text-zinc-400 bg-white rounded-2xl ring-1 ring-zinc-200">
                        <RefreshCcw size={18} className="mr-2 animate-spin" />
                        Chargement de l'inventaire...
                    </div>
                ) : (
                    // Si on a déjà des données, on garde le tableau visible mais on le rend légèrement transparent pendant qu'on tape
                    <div className={cn("transition-opacity duration-200", isLoading && "opacity-50 pointer-events-none")}>
                        <RoomTable
                            rooms={rooms}
                            onDeleteClick={setRoomToDelete}
                            onActivateClick={setRoomToActivate}
                        />
                    </div>
                )}
            </div>

            <DeleteRoomDialog
                isOpen={roomToDelete !== null}
                onClose={() => setRoomToDelete(null)}
                onConfirm={handleDeleteConfirm}
                roomNumber={roomToDelete?.number || ''}
                isLoading={isDeleting}
            />

            {/* Modale d'activation ajoutée ici */}
            <ActivateRoomDialog
                isOpen={roomToActivate !== null}
                onClose={() => setRoomToActivate(null)}
                onConfirm={handleActivateConfirm}
                roomNumber={roomToActivate?.number || ''}
                isLoading={isActivating}
            />
        </AppLayout>
    );
}
