"use client";

import { useEffect, useState } from "react";
import {
    Ban,
    CheckCircle2,
    Clock3,
    ListChecks,
    TriangleAlert,
} from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
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
        const timeoutId = window.setTimeout(() => {
            void loadHistory();
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, [roomId]);

    const doneCount = history.filter((item) => item.status === "DONE").length;
    const cancelledCount = history.filter((item) => item.status === "CANCELLED").length;
    const latestCleaning = history.find((item) => item.status === "DONE") ?? null;
    const roomNumber = history[0]?.roomNumber ?? String(roomId);

    return (
        <div className="space-y-8">
            <PageHeader
                backHref="/housekeeping/tasks"
                title={`Historique chambre ${roomNumber}`}
                description="Suivi chronologique des nettoyages, inspections et annulations pour cette chambre."
            />

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                    <div>
                        <p className="font-semibold">Erreur</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
                {[
                    {
                        label: "Total",
                        value: `${history.length} ${history.length > 1 ? "tâches" : "tâche"}`,
                        icon: ListChecks,
                        tone: "bg-zinc-100 text-zinc-700",
                    },
                    {
                        label: "Terminées",
                        value: `${doneCount} ${doneCount > 1 ? "terminées" : "terminée"}`,
                        icon: CheckCircle2,
                        tone: "bg-emerald-50 text-emerald-700",
                    },
                    {
                        label: "Annulées",
                        value: `${cancelledCount} ${cancelledCount > 1 ? "annulées" : "annulée"}`,
                        icon: Ban,
                        tone: "bg-red-50 text-red-700",
                    },
                    {
                        label: "Dernier nettoyage",
                        value: latestCleaning ? (
                            <HousekeepingDate value={latestCleaning.completedAt ?? latestCleaning.scheduledDate} />
                        ) : (
                            "—"
                        ),
                        icon: Clock3,
                        tone: "bg-blue-50 text-blue-700",
                    },
                ].map((card) => {
                    const Icon = card.icon;

                    return (
                        <HmsCard key={card.label} className="p-6">
                            <div className="flex items-start justify-between gap-4">
                                <div>
                                    <p className="text-sm font-medium text-[var(--hms-text-muted)]">
                                        {card.label}
                                    </p>
                                    <p className="mt-2 text-2xl font-bold tracking-tight text-[var(--hms-text)]">
                                        {card.value}
                                    </p>
                                </div>
                                <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl ${card.tone}`}>
                                    <Icon aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                                </div>
                            </div>
                        </HmsCard>
                    );
                })}
            </div>

            <HmsCard className="overflow-hidden p-0">
                <div className="border-b border-[var(--hms-soft-border)] px-4 py-5">
                    <h3 className="text-lg font-bold text-[var(--hms-text)]">
                        Historique chronologique
                    </h3>

                    <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                        {history.length} événement(s) de housekeeping pour cette chambre.
                    </p>
                </div>
                <RoomCleaningHistoryTable history={history} loading={isLoading} />
            </HmsCard>
        </div>
    );
}
