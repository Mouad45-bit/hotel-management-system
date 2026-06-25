"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ArrowLeft,
    LayoutDashboard,
    RefreshCw,
    TriangleAlert,
} from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingTaskTable } from "@/components/housekeeping/HousekeepingTaskTable";
import {
    cancelHousekeepingTask,
    completeHousekeepingTask,
    getHousekeepingTasksByAgentId,
    startHousekeepingTask,
} from "@/services/housekeepingApi";
import type { HousekeepingTask } from "@/types/housekeeping";

interface MyHousekeepingTasksClientProps {
    agentId: number;
}

export function MyHousekeepingTasksClient({ agentId }: MyHousekeepingTasksClientProps) {
    const [tasks, setTasks] = useState<HousekeepingTask[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [actionLoadingId, setActionLoadingId] = useState<number | null>(null);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    async function loadTasks() {
        setIsLoading(true);
        setErrorMessage(null);

        try {
            const agentTasks = await getHousekeepingTasksByAgentId(agentId);
            setTasks(agentTasks);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de charger vos tâches housekeeping."
            );
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        const timeoutId = window.setTimeout(() => {
            void loadTasks();
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, [agentId]);

    async function runAction(
        task: HousekeepingTask,
        callback: () => Promise<HousekeepingTask>
    ) {
        setActionLoadingId(task.id);
        setErrorMessage(null);

        try {
            await callback();
            await loadTasks();
        } catch (error) {
            setErrorMessage(
                error instanceof Error ? error.message : "Action impossible."
            );
        } finally {
            setActionLoadingId(null);
        }
    }

    return (
        <div className="space-y-8">
            <section>
                <Link
                    href="/housekeeping"
                    className="inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-3 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                >
                    <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                    Retour au dashboard
                </Link>

                <div className="mt-6 flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
                    <div>
                    <p className="text-xs font-bold uppercase tracking-[0.18em] text-[var(--hms-text-muted)]">
                        Agent simulé #{agentId}
                    </p>

                    <h2 className="mt-3 text-4xl font-extrabold tracking-tight text-[var(--hms-text)]">
                        Mes tâches housekeeping
                    </h2>

                    <p className="mt-4 max-w-3xl text-base leading-7 text-[var(--hms-text-muted)]">
                        Suivi personnel des tâches affectées à l’agent connecté simulé.
                    </p>
                    </div>

                    <Link
                        href="/housekeeping"
                        className="inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl border border-[var(--hms-border)] bg-white px-4 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                    >
                        <LayoutDashboard aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        Dashboard
                    </Link>
                </div>
            </section>

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                    <div>
                        <p className="font-semibold">Erreur</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            <HmsCard className="overflow-hidden p-0">
                <div className="flex flex-col gap-2 border-b border-[var(--hms-soft-border)] px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                        <p className="text-sm font-semibold text-[var(--hms-text-muted)]">
                            {tasks.length} tâche(s) pour l’agent #{agentId}
                        </p>
                    </div>

                    <HmsButton
                        type="button"
                        variant="secondary"
                        onClick={() => void loadTasks()}
                        disabled={isLoading}
                    >
                        <RefreshCw aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                        Actualiser
                    </HmsButton>
                </div>
                <HousekeepingTaskTable
                    tasks={tasks}
                    loading={isLoading}
                    actionLoadingId={actionLoadingId}
                    emptyMessage="Aucune tâche ne vous est assignée."
                    onStart={(task) => void runAction(task, () => startHousekeepingTask(task.id))}
                    onComplete={(task) =>
                        void runAction(task, () => completeHousekeepingTask(task.id))
                    }
                    onCancel={(task) =>
                        void runAction(task, () =>
                            cancelHousekeepingTask(task.id, {
                                reason: "Annulation depuis My tasks.",
                            })
                        )
                    }
                />
            </HmsCard>
        </div>
    );
}
