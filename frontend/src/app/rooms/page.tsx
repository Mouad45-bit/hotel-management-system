"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import type { Room, RoomStats } from "@/types/room";
import { RoomService, type RoomFilters as FilterTypes } from "@/services/room.service";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { Plus, RefreshCw, AlertCircle } from "lucide-react";

import { RoomFilters } from "@/components/rooms/RoomFilters";
import { RoomTable } from "@/components/rooms/RoomTable";
import { DeleteRoomDialog } from "@/components/rooms/DeleteRoomDialog";
import { RoomStatsCards } from "@/components/rooms/RoomStatsCards";
import { ActivateRoomDialog } from "@/components/rooms/ActivateRoomDialog";

const PAGE_SIZE = 10;

export default function RoomsPage() {
    const [rooms, setRooms] = useState<Room[]>([]);
    const [stats, setStats] = useState<RoomStats | null>(null);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filters, setFilters] = useState<FilterTypes>({});
    const [showInactive, setShowInactive] = useState(false);
    const [currentPage, setCurrentPage] = useState(0);

    const [roomToDelete, setRoomToDelete] = useState<Room | null>(null);
    const [isDeleting, setIsDeleting] = useState(false);

    const [roomToActivate, setRoomToActivate] = useState<Room | null>(null);
    const [isActivating, setIsActivating] = useState(false);

    const loadData = useCallback(async (activeFilters: FilterTypes, isInactive: boolean) => {
        setLoading(true);
        setError(null);
        try {
            const [roomsData, statsData] = await Promise.all([
                isInactive ? RoomService.getDisabledRooms() : RoomService.getRooms(activeFilters),
                RoomService.getStats(),
            ]);

            let finalRooms = roomsData;
            if (isInactive && activeFilters.number) {
                finalRooms = finalRooms.filter((r) => r.number.includes(activeFilters.number!));
            }

            setRooms(finalRooms);
            setStats(statsData);
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

    const totalPages = Math.max(1, Math.ceil(rooms.length / PAGE_SIZE));
    const paginatedRooms = rooms.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);

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

    return (
        <AppLayout>
            <PageHeader
                title="Chambres"
                description="Suivez les chambres, leurs statuts et leur disponibilité."
                actions={
                    <>
                        <HmsButton
                            variant="secondary"
                            onClick={handleInactiveToggle}
                            className={showInactive ? "border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100" : undefined}
                        >
                            {showInactive ? "Retour aux actives" : "Chambres désactivées"}
                        </HmsButton>
                        <Link href="/rooms/create">
                            <HmsButton>
                                <Plus className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                Nouvelle chambre
                            </HmsButton>
                        </Link>
                    </>
                }
            />

            <div className="space-y-6">
                {!error && !showInactive && <RoomStatsCards stats={stats} loading={isLoading} />}

                {error ? (
                    <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                        <div>
                            <p className="font-semibold">Erreur de chargement</p>
                            <p className="mt-1">{error}</p>
                            <button
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
                                {isLoading && rooms.length === 0
                                    ? "Chargement des chambres"
                                    : `${rooms.length} chambre${rooms.length > 1 ? "s" : ""} trouvée${rooms.length > 1 ? "s" : ""}`}
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

                                <RoomFilters
                                    filters={filters}
                                    onFilterChange={applyFilter}
                                />
                            </div>
                        </div>

                        <RoomTable
                            rooms={paginatedRooms}
                            loading={isLoading}
                            emptyMessage="Aucune chambre ne correspond aux filtres."
                            onDeleteClick={setRoomToDelete}
                            onActivateClick={setRoomToActivate}
                        />

                        <div className="flex items-center justify-between border-t border-[var(--hms-soft-border)] px-6 py-5">
                            <p className="text-sm text-[var(--hms-text-muted)]">
                                Page <span className="font-medium text-[var(--hms-text)]">{currentPage + 1}</span> sur <span className="font-medium text-[var(--hms-text)]">{totalPages}</span>
                            </p>
                            <div className="flex items-center gap-2">
                                <HmsButton variant="secondary" onClick={() => setCurrentPage((p) => p - 1)} disabled={isLoading || currentPage === 0} className="min-h-10 px-3">
                                    Précédent
                                </HmsButton>
                                <HmsButton variant="secondary" onClick={() => setCurrentPage((p) => p + 1)} disabled={isLoading || currentPage >= totalPages - 1} className="min-h-10 px-3">
                                    Suivant
                                </HmsButton>
                            </div>
                        </div>
                    </HmsCard>
                )}
            </div>

            <DeleteRoomDialog
                isOpen={roomToDelete !== null}
                onClose={() => setRoomToDelete(null)}
                onConfirm={handleDeleteConfirm}
                roomNumber={roomToDelete?.number || ""}
                isLoading={isDeleting}
            />

            <ActivateRoomDialog
                isOpen={roomToActivate !== null}
                onClose={() => setRoomToActivate(null)}
                onConfirm={handleActivateConfirm}
                roomNumber={roomToActivate?.number || ""}
                isLoading={isActivating}
            />
        </AppLayout>
    );
}
