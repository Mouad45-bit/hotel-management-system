"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import type { Reservation } from "@/types/reservation";
import { ReservationService, type ReservationFilters as FilterTypes } from "@/services/reservation.service";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { Plus, RefreshCcw, AlertCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { RoomService } from "@/services/room.service";
import { ClientService } from "@/services/client.service";

import { ReservationFilters } from "@/components/reservations/ReservationFilters";
import { ReservationStatsCards } from "@/components/reservations/ReservationStatsCards";
import { ReservationTable } from "@/components/reservations/ReservationTable";
import { CancelReservationDialog } from "@/components/reservations/CancelReservationDialog";

const PAGE_SIZE = 10;

export default function ReservationsPage() {
    const searchParams = useSearchParams();
    const initialRoomId = searchParams.get("roomId") ? Number(searchParams.get("roomId")) : undefined;
    const initialClientId = searchParams.get("clientId") ? Number(searchParams.get("clientId")) : undefined;

    const [reservations, setReservations] = useState<Reservation[]>([]);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filters, setFilters] = useState<FilterTypes>({
        ...(initialRoomId ? { roomId: initialRoomId } : {}),
        ...(initialClientId ? { clientId: initialClientId } : {}),
    });

    const [roomMap, setRoomMap] = useState<Record<number, string>>({});
    const [clientMap, setClientMap] = useState<Record<number, string>>({});

    const [currentPage, setCurrentPage] = useState(0);

    const [reservationToCancel, setReservationToCancel] = useState<Reservation | null>(null);
    const [isCancelling, setIsCancelling] = useState(false);

    const loadData = async (activeFilters: FilterTypes = filters) => {
        setLoading(true);
        setError(null);
        try {
            const [data, rooms, clients] = await Promise.all([
                ReservationService.getReservations(activeFilters),
                RoomService.getRooms(),
                ClientService.getClients(),
            ]);
            setReservations(data);
            const rMap: Record<number, string> = {};
            for (const room of rooms) rMap[room.id] = room.number;
            setRoomMap(rMap);
            const cMap: Record<number, string> = {};
            for (const client of clients) cMap[client.id] = `${client.firstName} ${client.lastName}`;
            setClientMap(cMap);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Erreur de connexion au serveur");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        void loadData();
    }, []);

    const applyFilter = (key: keyof FilterTypes, value: string) => {
        const updated = { ...filters, [key]: value || undefined };
        setFilters(updated);
        setCurrentPage(0);
        void loadData(updated);
    };

    const resetFilters = () => {
        setFilters({});
        setCurrentPage(0);
        void loadData({});
    };

    const totalPages = Math.max(1, Math.ceil(reservations.length / PAGE_SIZE));
    const paginatedReservations = reservations.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);

    const handleCancelConfirm = async () => {
        if (!reservationToCancel) return;
        setIsCancelling(true);
        try {
            await ReservationService.cancelReservation(reservationToCancel.id);
            setReservationToCancel(null);
            void loadData(filters);
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur lors de l'annulation");
            setReservationToCancel(null);
        } finally {
            setIsCancelling(false);
        }
    };

    return (
        <AppLayout>
            <PageHeader
                title="Gestion des réservations"
                description="Créez, suivez et gérez les réservations de l'hôtel. Chaque réservation relie un client à une chambre pour une période donnée."
                actions={
                    <Link href="/reservations/create">
                        <HmsButton>
                            <Plus className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                            Nouvelle réservation
                        </HmsButton>
                    </Link>
                }
            />

            <div className="space-y-6">
                {!error && reservations.length > 0 && (
                    <ReservationStatsCards reservations={reservations} />
                )}

                {(initialRoomId || initialClientId) && (
                    <HmsCard className="flex items-center justify-between bg-indigo-50">
                        <p className="text-sm font-medium text-indigo-700">
                            {initialRoomId && `Filtré par chambre #${initialRoomId}`}
                            {initialClientId && `Filtré par client #${initialClientId}`}
                        </p>
                        <Link href="/reservations" className="text-sm font-semibold text-indigo-600 hover:text-indigo-800">
                            Voir toutes
                        </Link>
                    </HmsCard>
                )}

                <ReservationFilters
                    filters={filters}
                    onFilterChange={applyFilter}
                    onReset={resetFilters}
                    count={reservations.length}
                />

                {error ? (
                    <HmsCard>
                        <div className="flex items-start gap-4">
                            <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" strokeWidth={1.8} />
                            <div>
                                <p className="font-semibold text-red-700">Impossible de contacter le serveur</p>
                                <p className="mt-1 text-sm text-red-600">{error}</p>
                                <button
                                    onClick={() => void loadData(filters)}
                                    className="mt-3 text-sm font-medium text-red-700 underline transition hover:text-red-900"
                                >
                                    Réessayer
                                </button>
                            </div>
                        </div>
                    </HmsCard>
                ) : isLoading && reservations.length === 0 ? (
                    <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
                            {Array.from({ length: 6 }).map((_, i) => (
                                <HmsCard key={i} className="h-20 animate-pulse bg-slate-50">{null}</HmsCard>
                            ))}
                        </div>
                        <HmsCard className="overflow-hidden p-0">
                            <div className="divide-y divide-[var(--hms-soft-border)]">
                                {Array.from({ length: 5 }).map((_, i) => (
                                    <div key={i} className="flex items-center gap-4 px-6 py-4">
                                        <div className="h-4 w-20 animate-pulse rounded bg-slate-100" />
                                        <div className="h-4 w-28 animate-pulse rounded bg-slate-100" />
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
                            <ReservationTable
                                reservations={paginatedReservations}
                                onCancelClick={setReservationToCancel}
                                roomMap={roomMap}
                                clientMap={clientMap}
                            />

                            {reservations.length > PAGE_SIZE && (
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

            <CancelReservationDialog
                isOpen={reservationToCancel !== null}
                onClose={() => setReservationToCancel(null)}
                onConfirm={handleCancelConfirm}
                reservationId={reservationToCancel?.id ?? 0}
                isLoading={isCancelling}
            />
        </AppLayout>
    );
}
