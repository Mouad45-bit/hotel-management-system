"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import type { Reservation } from "@/types/reservation";
import { ReservationService, type ReservationFilters as FilterTypes } from "@/services/reservation.service";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { Plus, RefreshCw, AlertCircle } from "lucide-react";
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
    const initialFilters = useMemo<FilterTypes>(() => ({
        ...(initialRoomId ? { roomId: initialRoomId } : {}),
        ...(initialClientId ? { clientId: initialClientId } : {}),
    }), [initialClientId, initialRoomId]);

    const [reservations, setReservations] = useState<Reservation[]>([]);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filters, setFilters] = useState<FilterTypes>(initialFilters);

    const [roomMap, setRoomMap] = useState<Record<number, string>>({});
    const [clientMap, setClientMap] = useState<Record<number, string>>({});

    const [currentPage, setCurrentPage] = useState(0);

    const [reservationToCancel, setReservationToCancel] = useState<Reservation | null>(null);
    const [isCancelling, setIsCancelling] = useState(false);

    const loadData = useCallback(async (activeFilters: FilterTypes) => {
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
    }, []);

    useEffect(() => {
        const timeoutId = window.setTimeout(() => {
            void loadData(initialFilters);
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, [initialFilters, loadData]);

    const applyFilter = (key: keyof FilterTypes, value: string) => {
        const updated = { ...filters, [key]: value || undefined };
        setFilters(updated);
        setCurrentPage(0);
        void loadData(updated);
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
                title="Réservations"
                description="Suivez les séjours, les chambres et les statuts de réservation."
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
                {!error && <ReservationStatsCards reservations={reservations} loading={isLoading} />}

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

                {error ? (
                    <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                        <div>
                            <p className="font-semibold">Erreur de chargement</p>
                            <p className="mt-1">{error}</p>
                            <button
                                type="button"
                                onClick={() => void loadData(filters)}
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
                                {isLoading && reservations.length === 0
                                    ? "Chargement des réservations"
                                    : `${reservations.length} réservation${reservations.length > 1 ? "s" : ""} trouvée${reservations.length > 1 ? "s" : ""}`}
                            </p>

                            <div className="flex items-center gap-1.5">
                                <HmsButton
                                    type="button"
                                    variant="secondary"
                                    onClick={() => void loadData(filters)}
                                    disabled={isLoading}
                                >
                                    <RefreshCw aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                    Actualiser
                                </HmsButton>

                                <ReservationFilters
                                    filters={filters}
                                    onFilterChange={applyFilter}
                                />
                            </div>
                        </div>

                        <ReservationTable
                            reservations={paginatedReservations}
                            loading={isLoading}
                            emptyMessage="Aucune réservation ne correspond aux filtres."
                            onCancelClick={setReservationToCancel}
                            roomMap={roomMap}
                            clientMap={clientMap}
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
