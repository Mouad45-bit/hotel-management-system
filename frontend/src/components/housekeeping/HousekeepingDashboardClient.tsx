"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ClipboardDocumentListIcon,
    ExclamationTriangleIcon,
    PlusIcon,
    UserCircleIcon,
} from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingStatsCards } from "@/components/housekeeping/HousekeepingStatsCards";
import { TodayHousekeepingTasks } from "@/components/housekeeping/TodayHousekeepingTasks";
import {
    getHousekeepingStats,
    getTodayHousekeepingTasks,
} from "@/services/housekeepingApi";
import type { HousekeepingStats, HousekeepingTask } from "@/types/housekeeping";

const EMPTY_STATS: HousekeepingStats = {
    total: 0,
    todo: 0,
    inProgress: 0,
    done: 0,
    cancelled: 0,
    urgent: 0,
    unassigned: 0,
};

export function HousekeepingDashboardClient() {
    const [stats, setStats] = useState<HousekeepingStats>(EMPTY_STATS);
    const [tasks, setTasks] = useState<HousekeepingTask[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    async function loadDashboard() {
        setIsLoading(true);
        setErrorMessage(null);

        try {
            const [loadedStats, todayTasks] = await Promise.all([
                getHousekeepingStats(),
                getTodayHousekeepingTasks(),
            ]);

            setStats(loadedStats);
            setTasks(todayTasks);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de charger le dashboard housekeeping."
            );
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        const timeoutId = window.setTimeout(() => {
            void loadDashboard();
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, []);

    const urgentTasks = tasks.filter((task) => task.priority === "URGENT");
    const unassignedTasks = tasks.filter((task) => !task.assignedAgentId);

    return (
        <div className="space-y-6">
            <HmsCard>
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                        <p className="text-sm font-medium text-stone-700">
                            Module Housekeeping
                        </p>
                        <h2 className="mt-2 text-xl font-semibold tracking-tight text-zinc-950">
                            Vue opérationnelle du jour
                        </h2>
                        <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-500">
                            Pilotez les chambres à nettoyer, les agents affectés et les statuts de remise en état avant remise en vente.
                        </p>
                    </div>

                    <div className="flex flex-col gap-2 sm:flex-row">
                        <Link
                            href="/housekeeping/tasks"
                            className="inline-flex items-center justify-center gap-2 rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50"
                        >
                            <ClipboardDocumentListIcon className="h-5 w-5" />
                            Liste
                        </Link>
                        <Link
                            href="/housekeeping/tasks/create"
                            className="inline-flex items-center justify-center gap-2 rounded-xl bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800"
                        >
                            <PlusIcon className="h-5 w-5" />
                            Créer
                        </Link>
                        <Link
                            href="/housekeeping/my-tasks"
                            className="inline-flex items-center justify-center gap-2 rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50"
                        >
                            <UserCircleIcon className="h-5 w-5" />
                            My tasks
                        </Link>
                    </div>
                </div>
            </HmsCard>

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0" />
                    <div>
                        <p className="font-semibold">Erreur de chargement</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            <HousekeepingStatsCards stats={stats} loading={isLoading} />

            <TodayHousekeepingTasks
                title="Tâches du jour"
                description="Nettoyages, inspections et remises en état planifiés aujourd’hui."
                tasks={tasks}
                loading={isLoading}
                emptyMessage="Aucune tâche planifiée aujourd’hui."
            />

            <div className="grid gap-6 xl:grid-cols-2">
                <TodayHousekeepingTasks
                    title="Tâches urgentes"
                    description="Priorités à traiter avant remise en vente."
                    tasks={urgentTasks}
                    loading={isLoading}
                    emptyMessage="Aucune tâche urgente."
                />
                <TodayHousekeepingTasks
                    title="Tâches non assignées"
                    description="Tâches à affecter à un agent housekeeping."
                    tasks={unassignedTasks}
                    loading={isLoading}
                    emptyMessage="Toutes les tâches sont assignées."
                />
            </div>
        </div>
    );
}
