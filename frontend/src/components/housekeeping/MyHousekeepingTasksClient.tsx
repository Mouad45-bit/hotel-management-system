"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
    CheckCircle2,
    Eye,
    FileText,
    Play,
    RefreshCw,
    TriangleAlert,
} from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingDate } from "@/components/housekeeping/HousekeepingDate";
import { HousekeepingStatusBadge } from "@/components/housekeeping/HousekeepingStatusBadge";
import { PriorityBadge } from "@/components/housekeeping/PriorityBadge";
import { TaskTypeBadge } from "@/components/housekeeping/TaskTypeBadge";
import {
    canCompleteTask,
    canStartTask,
} from "@/lib/housekeepingHelpers";
import {
    completeHousekeepingTask,
    getHousekeepingTasksByAgentId,
    startHousekeepingTask,
} from "@/services/housekeepingApi";
import type { HousekeepingTask } from "@/types/housekeeping";
import { useAuth } from "@/contexts/AuthContext";
import { getEmployees } from "@/services/staffApi";

interface MyTasksTableProps {
    tasks: HousekeepingTask[];
    loading?: boolean;
    emptyMessage?: string;
    actionLoadingId?: number | null;
    onStart?: (task: HousekeepingTask) => void;
    onComplete?: (task: HousekeepingTask) => void;
}

function formatAssignedTaskCount(count: number) {
    return `${count} ${count > 1 ? "tâches assignées" : "tâche assignée"}`;
}

function MyTasksTable({
    tasks,
    loading = false,
    emptyMessage = "Aucune tâche trouvée.",
    actionLoadingId = null,
    onStart,
    onComplete,
}: MyTasksTableProps) {
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
                        Les tâches assignées apparaîtront ici dès leur planification.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="w-full table-auto border-collapse">
                <thead className="bg-slate-50">
                    <tr>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Chambre
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Intervention
                        </th>
                        <th className="w-[1%] whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">
                            Priorité
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

                                <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center align-top">
                                    <TaskTypeBadge type={task.type} />
                                </td>

                                <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-center align-top">
                                    <PriorityBadge priority={task.priority} />
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
                                        {canStartTask(task) && onStart && (
                                            <button
                                                type="button"
                                                onClick={() => onStart(task)}
                                                disabled={disabled}
                                                className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-primary)] bg-[var(--hms-primary)] text-white transition-colors hover:bg-[var(--hms-primary-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-60"
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
                                        <Link
                                            href={`/housekeeping/tasks/${task.id}`}
                                            className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                            aria-label={`Voir la tâche ${task.id}`}
                                            title="Voir"
                                        >
                                            <Eye aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                        </Link>
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

const DEMO_HOUSEKEEPING_AGENT_ID = 101;

export function MyHousekeepingTasksClient() {
    const { user } = useAuth();
    const searchParams = useSearchParams();
    const [tasks, setTasks] = useState<HousekeepingTask[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [actionLoadingId, setActionLoadingId] = useState<number | null>(null);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [agentId, setAgentId] = useState<number | null>(null);
    const hasUnauthorizedMessage = searchParams.get("unauthorized") === "1";

    useEffect(() => {
        if (!user) return;

        getEmployees({ page: 0, size: 1000 })
            .then((employeesPage) => {
                const linkedEmployee = employeesPage.content.find(
                    (employee) => employee.authUserId === user.id
                );
                setAgentId(linkedEmployee?.id ?? DEMO_HOUSEKEEPING_AGENT_ID);
            })
            .catch(() => setAgentId(DEMO_HOUSEKEEPING_AGENT_ID));
    }, [user]);

    async function loadTasks() {
        if (!agentId) return;
        setIsLoading(true);
        setErrorMessage(null);

        try {
            const agentTasks = await getHousekeepingTasksByAgentId(agentId);
            const statusFilter = searchParams.get("status");
            setTasks(
                statusFilter === "TODO" || statusFilter === "IN_PROGRESS"
                    ? agentTasks.filter((task) => task.status === statusFilter)
                    : agentTasks
            );
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
    }, [agentId, searchParams]);

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
            <PageHeader
                title="Mes tâches"
                description="Suivez vos tâches assignées et mettez à jour leur avancement."
            />

            {hasUnauthorizedMessage && (
                <div className="rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-medium text-amber-800">
                    Accès non autorisé. Cette tâche ne vous est pas affectée.
                </div>
            )}

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
                            {formatAssignedTaskCount(tasks.length)}
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
                <MyTasksTable
                    tasks={tasks}
                    loading={isLoading}
                    actionLoadingId={actionLoadingId}
                    emptyMessage="Aucune tâche ne vous est assignée."
                    onStart={(task) => void runAction(task, () => startHousekeepingTask(task.id))}
                    onComplete={(task) =>
                        void runAction(task, () => completeHousekeepingTask(task.id))
                    }
                />
            </HmsCard>
        </div>
    );
}
