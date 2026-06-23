"use client";

import Link from "next/link";
import {
    CheckCircleIcon,
    EyeIcon,
    NoSymbolIcon,
    PlayIcon,
    UserPlusIcon,
} from "@heroicons/react/24/outline";
import { HousekeepingDate } from "@/components/housekeeping/HousekeepingDate";
import { HousekeepingStatusBadge } from "@/components/housekeeping/HousekeepingStatusBadge";
import { PriorityBadge } from "@/components/housekeeping/PriorityBadge";
import { TaskTypeBadge } from "@/components/housekeeping/TaskTypeBadge";
import {
    canAssignTask,
    canCancelTask,
    canCompleteTask,
    canStartTask,
} from "@/lib/housekeepingHelpers";
import type { HousekeepingTask } from "@/types/housekeeping";

interface HousekeepingTaskTableProps {
    tasks: HousekeepingTask[];
    loading?: boolean;
    emptyMessage?: string;
    actionLoadingId?: number | null;
    onAssign?: (task: HousekeepingTask) => void;
    onStart?: (task: HousekeepingTask) => void;
    onComplete?: (task: HousekeepingTask) => void;
    onCancel?: (task: HousekeepingTask) => void;
}

export function HousekeepingTaskTable({
    tasks,
    loading = false,
    emptyMessage = "Aucune tâche trouvée.",
    actionLoadingId = null,
    onAssign,
    onStart,
    onComplete,
    onCancel,
}: HousekeepingTaskTableProps) {
    if (loading && tasks.length === 0) {
        return (
            <div className="divide-y divide-zinc-100">
                {Array.from({ length: 5 }).map((_, index) => (
                    <div key={index} className="grid gap-4 px-6 py-4 md:grid-cols-7">
                        {Array.from({ length: 7 }).map((__, cellIndex) => (
                            <div
                                key={cellIndex}
                                className="h-5 animate-pulse rounded-lg bg-zinc-100"
                            />
                        ))}
                    </div>
                ))}
            </div>
        );
    }

    if (tasks.length === 0) {
        return (
            <div className="flex min-h-60 items-center justify-center px-6 py-12">
                <div className="text-center">
                    <p className="text-sm font-medium text-zinc-900">
                        {emptyMessage}
                    </p>
                    <p className="mt-1 text-sm text-zinc-500">
                        Essayez de modifier les filtres ou de créer une tâche manuelle.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-zinc-200">
                <thead className="bg-zinc-50">
                    <tr>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Chambre
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Type
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Priorité
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Agent
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Planifiée
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Statut
                        </th>
                        <th className="px-6 py-3 text-right text-xs font-semibold uppercase tracking-wide text-zinc-500">
                            Actions
                        </th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100 bg-white">
                    {tasks.map((task) => {
                        const disabled = actionLoadingId === task.id;

                        return (
                            <tr key={task.id} className="transition hover:bg-stone-50/60">
                                <td className="whitespace-nowrap px-6 py-4">
                                    <p className="text-sm font-semibold text-zinc-950">
                                        Chambre {task.roomNumber}
                                    </p>
                                    <p className="mt-1 text-xs text-zinc-500">
                                        Tâche #{task.id}
                                    </p>
                                </td>
                                <td className="whitespace-nowrap px-6 py-4">
                                    <TaskTypeBadge type={task.type} />
                                </td>
                                <td className="whitespace-nowrap px-6 py-4">
                                    <PriorityBadge priority={task.priority} />
                                </td>
                                <td className="whitespace-nowrap px-6 py-4">
                                    <p className="text-sm font-medium text-zinc-900">
                                        {task.assignedAgentName ?? "Non assignée"}
                                    </p>
                                    {task.assignedAgentId && (
                                        <p className="mt-1 text-xs text-zinc-500">
                                            Agent #{task.assignedAgentId}
                                        </p>
                                    )}
                                </td>
                                <td className="whitespace-nowrap px-6 py-4">
                                    <HousekeepingDate value={task.scheduledDate} />
                                </td>
                                <td className="whitespace-nowrap px-6 py-4">
                                    <HousekeepingStatusBadge status={task.status} />
                                </td>
                                <td className="min-w-96 px-6 py-4 text-right">
                                    <div className="flex flex-wrap justify-end gap-2">
                                        <Link
                                            href={`/housekeeping/tasks/${task.id}`}
                                            className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs font-semibold text-zinc-700 transition hover:bg-zinc-50"
                                        >
                                            <EyeIcon className="h-4 w-4" />
                                            Voir
                                        </Link>
                                        {canAssignTask(task) && onAssign && (
                                            <button
                                                type="button"
                                                onClick={() => onAssign(task)}
                                                disabled={disabled}
                                                className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-60"
                                            >
                                                <UserPlusIcon className="h-4 w-4" />
                                                Assigner
                                            </button>
                                        )}
                                        {canStartTask(task) && onStart && (
                                            <button
                                                type="button"
                                                onClick={() => onStart(task)}
                                                disabled={disabled}
                                                className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-60"
                                            >
                                                <PlayIcon className="h-4 w-4" />
                                                Démarrer
                                            </button>
                                        )}
                                        {canCompleteTask(task) && onComplete && (
                                            <button
                                                type="button"
                                                onClick={() => onComplete(task)}
                                                disabled={disabled}
                                                className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-xs font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-60"
                                            >
                                                <CheckCircleIcon className="h-4 w-4" />
                                                Terminer
                                            </button>
                                        )}
                                        {canCancelTask(task) && onCancel && (
                                            <button
                                                type="button"
                                                onClick={() => onCancel(task)}
                                                disabled={disabled}
                                                className="inline-flex items-center gap-1.5 rounded-xl border border-red-200 bg-white px-3 py-2 text-xs font-semibold text-red-700 transition hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-60"
                                            >
                                                <NoSymbolIcon className="h-4 w-4" />
                                                Annuler
                                            </button>
                                        )}
                                    </div>
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}
