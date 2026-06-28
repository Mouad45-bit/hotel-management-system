"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { Room, RoomStats } from "@/types/room";
import { RoomService, type RoomFilters as FilterTypes } from "@/services/room.service";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { Plus, RefreshCcw, AlertCircle } from "lucide-react";
import { cn } from "@/lib/utils";

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

    const loadData = async (activeFilters: FilterTypes = filters, isInactive: boolean = showInactive) => {
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
                title="Gestion des chambres"
                description="Créez, suivez et pilotez l'inventaire des chambres. Cette interface affiche les chambres avec recherche, filtrage, statut métier et activation administrative."
                actions={
                    <>
                        <HmsButton
                            variant={showInactive ? "primary" : "secondary"}
                            onClick={() => setShowInactive(!showInactive)}
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
                {!error && stats && !showInactive && <RoomStatsCards stats={stats} />}

                <RoomFilters
                    filters={filters}
                    onFilterChange={applyFilter}
                    onReset={resetFilters}
                    count={rooms.length}
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
                ) : isLoading && rooms.length === 0 ? (
                    <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-7">
                            {Array.from({ length: 7 }).map((_, i) => (
                                <HmsCard key={i} className="h-20 animate-pulse bg-slate-50">{null}</HmsCard>
                            ))}
                        </div>
                        <HmsCard className="overflow-hidden p-0">
                            <div className="divide-y divide-[var(--hms-soft-border)]">
                                {Array.from({ length: 5 }).map((_, i) => (
                                    <div key={i} className="flex items-center gap-4 px-6 py-4">
                                        <div className="h-4 w-16 animate-pulse rounded bg-slate-100" />
                                        <div className="h-4 w-24 animate-pulse rounded bg-slate-100" />
                                        <div className="h-4 w-20 animate-pulse rounded bg-slate-100" />
                                        <div className="ml-auto h-4 w-16 animate-pulse rounded bg-slate-100" />
                                    </div>
                                ))}
                            </div>
                        </HmsCard>
                    </div>
                ) : (
                    <div className={cn("transition-opacity duration-200", isLoading && "pointer-events-none opacity-50")}>
                        <HmsCard className="overflow-hidden p-0">
                            <RoomTable
                                rooms={paginatedRooms}
                                onDeleteClick={setRoomToDelete}
                                onActivateClick={setRoomToActivate}
                            />

                            {rooms.length > PAGE_SIZE && (
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
