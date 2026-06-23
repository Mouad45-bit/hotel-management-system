"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ArrowPathIcon,
    ExclamationTriangleIcon,
    UserCircleIcon,
} from "@heroicons/react/24/outline";
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
        <div className="space-y-6">
            <HmsCard>
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                        <p className="text-sm font-medium text-stone-700">
                            Agent simulé #{agentId}
                        </p>
                        <h2 className="mt-2 text-xl font-semibold tracking-tight text-zinc-950">
                            Mes tâches housekeeping
                        </h2>
                        <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-500">
                            Cette vue n’affiche que les tâches assignées à l’agent connecté simulé.
                        </p>
                    </div>
                    <Link
                        href="/housekeeping"
                        className="inline-flex items-center justify-center gap-2 rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50"
                    >
                        <UserCircleIcon className="h-5 w-5" />
                        Dashboard
                    </Link>
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

            <HmsCard className="p-0">
                <div className="flex flex-col gap-3 border-b border-zinc-200 px-6 py-4 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                        <h3 className="text-sm font-semibold text-zinc-950">
                            Tâches assignées
                        </h3>
                        <p className="mt-1 text-sm text-zinc-500">
                            {tasks.length} tâche(s) pour l’agent #{agentId}
                        </p>
                    </div>
                    <button
                        type="button"
                        onClick={() => void loadTasks()}
                        disabled={isLoading}
                        className="inline-flex items-center justify-center gap-2 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                        <ArrowPathIcon className="h-4 w-4" />
                        Actualiser
                    </button>
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
