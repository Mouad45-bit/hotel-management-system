"use client";

import Link from "next/link";
import {
    Ban,
    CheckCircle2,
    Eye,
    FileText,
    Play,
    UserPlus,
} from "lucide-react";
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
            <div className="divide-y divide-[var(--hms-soft-border)]">
                {Array.from({ length: 5 }).map((_, index) => (
                    <div key={index} className="grid gap-3 px-4 py-4 md:grid-cols-7">
                        {Array.from({ length: 7 }).map((__, cellIndex) => (
                            <div
                                key={cellIndex}
                                className="h-5 animate-pulse rounded-lg bg-slate-100"
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
                    <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <FileText aria-hidden="true" className="h-6 w-6" strokeWidth={1.8} />
                    </div>

                    <p className="mt-4 text-sm font-semibold text-[var(--hms-text)]">
                        {emptyMessage}
                    </p>

                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">
                        Essayez de modifier les filtres ou de créer une tâche manuelle.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-visible">
            <table className="w-full table-auto border-collapse">
                <thead className="bg-slate-50">
                    <tr>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Chambre
                        </th>
                        <th className="border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Intervention
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Agent
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Planifiée
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Statut
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Actions
                        </th>
                    </tr>
                </thead>
                <tbody className="bg-white">
                    {tasks.map((task) => {
                        const disabled = actionLoadingId === task.id;

                        return (
                            <tr key={task.id} className="transition-colors hover:bg-slate-50">
                                <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                    <p className="text-sm font-bold text-[var(--hms-text)]">
                                        Chambre {task.roomNumber}
                                    </p>

                                    <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                        Tâche #{task.id}
                                    </p>
                                </td>

                                <td className="border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                    <div className="flex flex-wrap gap-2">
                                        <TaskTypeBadge type={task.type} />
                                        <PriorityBadge priority={task.priority} />
                                    </div>
                                </td>

                                <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                    <p className="text-sm font-semibold text-[var(--hms-text)]">
                                        {task.assignedAgentName ?? "Non assignée"}
                                    </p>

                                    {task.assignedAgentId && (
                                        <p className="mt-1 text-xs text-[var(--hms-text-muted)]">
                                            Agent #{task.assignedAgentId}
                                        </p>
                                    )}
                                </td>

                                <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                    <HousekeepingDate
                                        value={task.scheduledDate}
                                        className="text-sm text-[var(--hms-text)]"
                                    />
                                </td>

                                <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center align-top">
                                    <HousekeepingStatusBadge status={task.status} />
                                </td>

                                <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right align-top">
                                    <div className="flex justify-end gap-1.5">
                                        <Link
                                            href={`/housekeeping/tasks/${task.id}`}
                                            className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                            aria-label={`Voir la tâche ${task.id}`}
                                            title="Voir"
                                        >
                                            <Eye aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                        </Link>
                                        {canAssignTask(task) && onAssign && (
                                            <button
                                                type="button"
                                                onClick={() => onAssign(task)}
                                                disabled={disabled}
                                                className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-60"
                                                aria-label={`Affecter la tâche ${task.id}`}
                                                title="Affecter"
                                            >
                                                <UserPlus aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                            </button>
                                        )}
                                        {canStartTask(task) && onStart && (
                                            <button
                                                type="button"
                                                onClick={() => onStart(task)}
                                                disabled={disabled}
                                                className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-60"
                                                aria-label={`Démarrer la tâche ${task.id}`}
                                                title="Démarrer"
                                            >
                                                <Play aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                            </button>
                                        )}
                                        {canCompleteTask(task) && onComplete && (
                                            <button
                                                type="button"
                                                onClick={() => onComplete(task)}
                                                disabled={disabled}
                                                className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-emerald-200 bg-white text-emerald-700 transition-colors hover:bg-emerald-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-60"
                                                aria-label={`Terminer la tâche ${task.id}`}
                                                title="Terminer"
                                            >
                                                <CheckCircle2 aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                            </button>
                                        )}
                                        {canCancelTask(task) && onCancel && (
                                            <button
                                                type="button"
                                                onClick={() => onCancel(task)}
                                                disabled={disabled}
                                                className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-red-200 bg-white text-red-700 transition-colors hover:bg-red-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-60"
                                                aria-label={`Annuler la tâche ${task.id}`}
                                                title="Annuler"
                                            >
                                                <Ban aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
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
