"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ClipboardList,
    Plus,
    TriangleAlert,
    UserRoundCheck,
    UserRoundPlus,
} from "lucide-react";
import { TodayHousekeepingTasks } from "@/components/housekeeping/TodayHousekeepingTasks";
import { getTodayHousekeepingTasks } from "@/services/housekeepingApi";
import type { HousekeepingTask } from "@/types/housekeeping";

export function HousekeepingDashboardClient() {
    const [tasks, setTasks] = useState<HousekeepingTask[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    async function loadDashboard() {
        setIsLoading(true);
        setErrorMessage(null);

        try {
            const todayTasks = await getTodayHousekeepingTasks();

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
        <div className="space-y-8">
            <section className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
                <div>
                    <h2 className="text-4xl font-extrabold tracking-tight text-[var(--hms-text)]">
                        Housekeeping
                    </h2>

                    <p className="mt-4 max-w-3xl text-base leading-7 text-[var(--hms-text-muted)]">
                        Suivez les chambres à nettoyer,
                        <br />
                        les priorités du jour et les tâches à affecter avant remise en vente.
                    </p>
                </div>

                <div className="flex flex-col gap-2 sm:flex-row">
                    <Link
                        href="/housekeeping/my-tasks"
                        className="inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl border border-[var(--hms-border)] bg-white px-4 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                    >
                        <UserRoundCheck aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        Mes tâches
                    </Link>

                    <Link
                        href="/housekeeping/tasks"
                        className="inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl border border-[var(--hms-border)] bg-white px-4 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                    >
                        <ClipboardList aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        Liste des tâches
                    </Link>

                    <Link
                        href="/housekeeping/tasks/create"
                        className="inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl bg-[var(--hms-primary)] px-5 py-3 text-sm font-semibold text-white transition-colors hover:bg-[var(--hms-primary-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                    >
                        <Plus aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        Créer une tâche
                    </Link>
                </div>
            </section>

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                    <div>
                        <p className="font-semibold">Erreur de chargement</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            <div className="grid gap-6 xl:grid-cols-2">
                <TodayHousekeepingTasks
                    title="Tâches urgentes"
                    description="Priorités à traiter rapidement, sans surcharge visuelle."
                    tasks={urgentTasks}
                    loading={isLoading}
                    emptyMessage="Aucune tâche urgente."
                    icon={TriangleAlert}
                    tone="warning"
                    className="xl:col-span-2"
                />

                <TodayHousekeepingTasks
                    title="Tâches du jour"
                    description="Nettoyages, inspections et remises en état planifiés aujourd’hui."
                    tasks={tasks}
                    loading={isLoading}
                    emptyMessage="Aucune tâche planifiée aujourd’hui."
                    icon={ClipboardList}
                    tone="default"
                    className="xl:col-span-2"
                />

                <TodayHousekeepingTasks
                    title="Tâches non assignées"
                    description="Tâches à affecter à un agent housekeeping."
                    tasks={unassignedTasks}
                    loading={isLoading}
                    emptyMessage="Toutes les tâches sont assignées."
                    icon={UserRoundPlus}
                    tone="info"
                    className="xl:col-span-2"
                />
            </div>
        </div>
    );
}
