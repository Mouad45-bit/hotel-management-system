"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ArrowLeftIcon,
    ExclamationTriangleIcon,
    HomeIcon,
} from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingDate } from "@/components/housekeeping/HousekeepingDate";
import { RoomCleaningHistoryTable } from "@/components/housekeeping/RoomCleaningHistoryTable";
import { getHousekeepingTasksByRoomId } from "@/services/housekeepingApi";
import type { RoomCleaningHistoryItem } from "@/types/housekeeping";

interface RoomCleaningHistoryClientProps {
    roomId: number;
}

export function RoomCleaningHistoryClient({ roomId }: RoomCleaningHistoryClientProps) {
    const [history, setHistory] = useState<RoomCleaningHistoryItem[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    async function loadHistory() {
        if (!Number.isFinite(roomId) || roomId <= 0) {
            setErrorMessage("Identifiant de chambre invalide.");
            setIsLoading(false);
            return;
        }

        setIsLoading(true);
        setErrorMessage(null);

        try {
            const roomHistory = await getHousekeepingTasksByRoomId(roomId);
            setHistory(roomHistory);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de charger l’historique de la chambre."
            );
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        void loadHistory();
    }, [roomId]);

    const doneCount = history.filter((item) => item.status === "DONE").length;
    const cancelledCount = history.filter((item) => item.status === "CANCELLED").length;
    const latestCleaning = history.find((item) => item.status === "DONE") ?? null;
    const roomNumber = history[0]?.roomNumber ?? String(roomId);

    return (
        <div className="space-y-6">
            <HmsCard>
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                        <Link
                            href="/housekeeping/tasks"
                            className="inline-flex items-center gap-2 text-sm font-semibold text-zinc-700 transition hover:text-zinc-950"
                        >
                            <ArrowLeftIcon className="h-4 w-4" />
                            Retour aux tâches
                        </Link>
                        <div className="mt-5 flex items-center gap-3">
                            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-stone-900 text-white">
                                <HomeIcon className="h-5 w-5" />
                            </div>
                            <div>
                                <h2 className="text-2xl font-semibold tracking-tight text-zinc-950">
                                    Historique chambre {roomNumber}
                                </h2>
                                <p className="mt-1 text-sm text-zinc-500">
                                    Suivi chronologique des nettoyages, inspections et annulations.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </HmsCard>

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0" />
                    <div>
                        <p className="font-semibold">Erreur</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            <div className="grid gap-4 md:grid-cols-4">
                <HmsCard>
                    <p className="text-sm text-zinc-500">Total</p>
                    <p className="mt-2 text-2xl font-semibold text-zinc-950">
                        {history.length}
                    </p>
                </HmsCard>
                <HmsCard>
                    <p className="text-sm text-zinc-500">Terminées</p>
                    <p className="mt-2 text-2xl font-semibold text-emerald-700">
                        {doneCount}
                    </p>
                </HmsCard>
                <HmsCard>
                    <p className="text-sm text-zinc-500">Annulées</p>
                    <p className="mt-2 text-2xl font-semibold text-red-700">
                        {cancelledCount}
                    </p>
                </HmsCard>
                <HmsCard>
                    <p className="text-sm text-zinc-500">Dernier nettoyage</p>
                    <p className="mt-2 text-sm font-semibold text-zinc-950">
                        {latestCleaning ? (
                            <HousekeepingDate value={latestCleaning.completedAt ?? latestCleaning.scheduledDate} />
                        ) : (
                            "—"
                        )}
                    </p>
                </HmsCard>
            </div>

            <HmsCard className="p-0">
                <div className="border-b border-zinc-200 px-6 py-4">
                    <h3 className="text-sm font-semibold text-zinc-950">
                        Historique chronologique
                    </h3>
                    <p className="mt-1 text-sm text-zinc-500">
                        {history.length} événement(s) de housekeeping pour cette chambre.
                    </p>
                </div>
                <RoomCleaningHistoryTable history={history} loading={isLoading} />
            </HmsCard>
        </div>
    );
}
