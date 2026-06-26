'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { Reservation } from '@/types/reservation';
import { ReservationService, ReservationFilters as FilterTypes } from '@/services/reservation.service';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { Plus, RefreshCcw, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

import { ReservationFilters } from '@/components/reservations/ReservationFilters';
import { ReservationTable } from '@/components/reservations/ReservationTable';
import { CancelReservationDialog } from '@/components/reservations/CancelReservationDialog';

export default function ReservationsPage() {
    const searchParams = useSearchParams();
    const initialRoomId = searchParams.get('roomId') ? Number(searchParams.get('roomId')) : undefined;
    const initialClientId = searchParams.get('clientId') ? Number(searchParams.get('clientId')) : undefined;

    const [reservations, setReservations] = useState<Reservation[]>([]);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filters, setFilters] = useState<FilterTypes>({
        ...(initialRoomId ? { roomId: initialRoomId } : {}),
        ...(initialClientId ? { clientId: initialClientId } : {}),
    });

    const [reservationToCancel, setReservationToCancel] = useState<Reservation | null>(null);
    const [isCancelling, setIsCancelling] = useState(false);

    const loadData = async (activeFilters: FilterTypes = filters) => {
        setLoading(true);
        setError(null);
        try {
            const data = await ReservationService.getReservations(activeFilters);
            setReservations(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Erreur de connexion au serveur');
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
        void loadData(updated);
    };

    const resetFilters = () => {
        setFilters({});
        void loadData({});
    };

    const handleCancelConfirm = async () => {
        if (!reservationToCancel) return;
        setIsCancelling(true);
        try {
            await ReservationService.cancelReservation(reservationToCancel.id);
            setReservationToCancel(null);
            void loadData(filters);
        } catch (err) {
            alert(err instanceof Error ? err.message : 'Erreur lors de l\'annulation');
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
                    <Link
                        href="/reservations/create"
                        className="inline-flex items-center gap-2 rounded-2xl bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-zinc-800"
                    >
                        <Plus size={18} />
                        Nouvelle réservation
                    </Link>
                }
            />

            <div className="space-y-6">
                {(initialRoomId || initialClientId) && (
                    <div className="flex items-center justify-between rounded-2xl bg-indigo-50 px-5 py-3 ring-1 ring-indigo-200">
                        <p className="text-sm font-medium text-indigo-700">
                            {initialRoomId && `Filtré par chambre #${initialRoomId}`}
                            {initialClientId && `Filtré par client #${initialClientId}`}
                        </p>
                        <Link href="/reservations" className="text-sm font-semibold text-indigo-600 hover:text-indigo-800">
                            Voir toutes
                        </Link>
                    </div>
                )}

                <ReservationFilters
                    filters={filters}
                    onFilterChange={applyFilter}
                    onReset={resetFilters}
                    count={reservations.length}
                />

                {error ? (
                    <div className="flex items-start gap-4 rounded-2xl border border-red-200 bg-red-50 p-6">
                        <AlertCircle className="mt-0.5 shrink-0 text-red-500" size={20} />
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
                ) : isLoading && reservations.length === 0 ? (
                    <div className="flex items-center justify-center py-24 text-zinc-400 bg-white rounded-2xl ring-1 ring-zinc-200">
                        <RefreshCcw size={18} className="mr-2 animate-spin" />
                        Chargement des réservations...
                    </div>
                ) : (
                    <div className={cn('transition-opacity duration-200', isLoading && 'opacity-50 pointer-events-none')}>
                        <ReservationTable
                            reservations={reservations}
                            onCancelClick={setReservationToCancel}
                        />
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
