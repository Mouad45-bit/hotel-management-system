"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ArrowPathIcon,
    ExclamationTriangleIcon,
    PlusIcon,
} from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingStatsCards } from "@/components/housekeeping/HousekeepingStatsCards";
import { HousekeepingTaskFilters } from "@/components/housekeeping/HousekeepingTaskFilters";
import { HousekeepingTaskTable } from "@/components/housekeeping/HousekeepingTaskTable";
import {
    assignHousekeepingTask,
    cancelHousekeepingTask,
    completeHousekeepingTask,
    getHousekeepingAgents,
    getHousekeepingStats,
    getHousekeepingTasks,
    startHousekeepingTask,
} from "@/services/housekeepingApi";
import {
    housekeepingFiltersSchema,
    toHousekeepingSearchParams,
    type HousekeepingFiltersFormValues,
} from "@/schemas/housekeeping.schema";
import {
    DEFAULT_HOUSEKEEPING_FILTERS,
    type HousekeepingAgentOption,
    type HousekeepingStats,
    type HousekeepingTask,
    type HousekeepingTaskFiltersState,
    type PageResponse,
} from "@/types/housekeeping";

const PAGE_SIZE = 8;

const EMPTY_STATS: HousekeepingStats = {
    total: 0,
    todo: 0,
    inProgress: 0,
    done: 0,
    cancelled: 0,
    urgent: 0,
    unassigned: 0,
};

type FilterErrors = Partial<Record<keyof HousekeepingTaskFiltersState, string>>;

function extractFilterErrors(
    issues: { path: PropertyKey[]; message: string }[]
): FilterErrors {
    const errors: FilterErrors = {};

    issues.forEach((issue) => {
        const field = issue.path[0];

        if (typeof field === "string") {
            errors[field as keyof HousekeepingTaskFiltersState] = issue.message;
        }
    });

    return errors;
}

export function HousekeepingTasksListClient() {
    const [filters, setFilters] = useState<HousekeepingTaskFiltersState>(
        DEFAULT_HOUSEKEEPING_FILTERS
    );
    const [filterErrors, setFilterErrors] = useState<FilterErrors>({});
    const [pageResponse, setPageResponse] =
        useState<PageResponse<HousekeepingTask> | null>(null);
    const [stats, setStats] = useState<HousekeepingStats>(EMPTY_STATS);
    const [agents, setAgents] = useState<HousekeepingAgentOption[]>([]);
    const [currentPage, setCurrentPage] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [actionLoadingId, setActionLoadingId] = useState<number | null>(null);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    async function loadTasks(nextFilters: HousekeepingTaskFiltersState, page: number) {
        const validationResult = housekeepingFiltersSchema.safeParse(nextFilters);

        if (!validationResult.success) {
            setFilterErrors(extractFilterErrors(validationResult.error.issues));
            return;
        }

        setIsLoading(true);
        setErrorMessage(null);
        setFilterErrors({});

        try {
            const searchParams = toHousekeepingSearchParams(
                validationResult.data as HousekeepingFiltersFormValues
            );
            const [tasksPage, taskStats, agentOptions] = await Promise.all([
                getHousekeepingTasks({
                    ...searchParams,
                    page,
                    size: PAGE_SIZE,
                    sort: "scheduledDate,asc",
                }),
                getHousekeepingStats(),
                getHousekeepingAgents(),
            ]);

            setPageResponse(tasksPage);
            setStats(taskStats);
            setAgents(agentOptions);
            setCurrentPage(tasksPage.page);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de charger les tâches housekeeping."
            );
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        const timeoutId = window.setTimeout(() => {
            void loadTasks(DEFAULT_HOUSEKEEPING_FILTERS, 0);
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, []);

    function handleApplyFilters(nextFilters: HousekeepingTaskFiltersState) {
        setFilters(nextFilters);
        void loadTasks(nextFilters, 0);
    }

    function handleResetFilters() {
        setFilters(DEFAULT_HOUSEKEEPING_FILTERS);
        void loadTasks(DEFAULT_HOUSEKEEPING_FILTERS, 0);
    }

    function handlePreviousPage() {
        if (currentPage === 0) {
            return;
        }

        void loadTasks(filters, currentPage - 1);
    }

    function handleNextPage() {
        if (!pageResponse || pageResponse.last) {
            return;
        }

        void loadTasks(filters, currentPage + 1);
    }

    async function runAction(
        task: HousekeepingTask,
        callback: () => Promise<HousekeepingTask>
    ) {
        setActionLoadingId(task.id);
        setErrorMessage(null);

        try {
            await callback();
            await loadTasks(filters, currentPage);
        } catch (error) {
            setErrorMessage(
                error instanceof Error ? error.message : "Action impossible."
            );
        } finally {
            setActionLoadingId(null);
        }
    }

    function handleAssign(task: HousekeepingTask) {
        const fallbackAgent = agents.find((agent) => agent.id !== task.assignedAgentId) ?? agents[0];

        if (!fallbackAgent) {
            setErrorMessage("Aucun agent actif disponible pour l’assignation.");
            return;
        }

        void runAction(task, () =>
            assignHousekeepingTask(task.id, { assignedAgentId: fallbackAgent.id })
        );
    }

    function handleStart(task: HousekeepingTask) {
        void runAction(task, () => startHousekeepingTask(task.id));
    }

    function handleComplete(task: HousekeepingTask) {
        void runAction(task, () => completeHousekeepingTask(task.id));
    }

    function handleCancel(task: HousekeepingTask) {
        void runAction(task, () =>
            cancelHousekeepingTask(task.id, {
                reason: "Annulation opérationnelle depuis la liste.",
            })
        );
    }

    const tasks = pageResponse?.content ?? [];

    return (
        <div className="space-y-6">
            <HmsCard>
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                        <p className="text-sm font-medium text-stone-700">
                            Module Housekeeping
                        </p>
                        <h2 className="mt-2 text-xl font-semibold tracking-tight text-zinc-950">
                            Liste des tâches de nettoyage
                        </h2>
                        <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-500">
                            Suivez les tâches liées aux chambres, leur priorité, leur agent et leur statut opérationnel.
                        </p>
                    </div>
                    <Link
                        href="/housekeeping/tasks/create"
                        className="inline-flex items-center justify-center gap-2 rounded-xl bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800"
                    >
                        <PlusIcon className="h-5 w-5" />
                        Créer une tâche
                    </Link>
                </div>
            </HmsCard>

            <HousekeepingStatsCards stats={stats} loading={isLoading} />

            <HousekeepingTaskFilters
                filters={filters}
                errors={filterErrors}
                loading={isLoading}
                onApply={handleApplyFilters}
                onReset={handleResetFilters}
            />

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
                            Tableau des tâches
                        </h3>
                        <p className="mt-1 text-sm text-zinc-500">
                            {pageResponse
                                ? `${pageResponse.totalElements} tâche(s) trouvée(s)`
                                : "Chargement des tâches"}
                        </p>
                    </div>
                    <button
                        type="button"
                        onClick={() => void loadTasks(filters, currentPage)}
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
                    emptyMessage="Aucune tâche ne correspond aux filtres."
                    onAssign={handleAssign}
                    onStart={handleStart}
                    onComplete={handleComplete}
                    onCancel={handleCancel}
                />

                <div className="flex items-center justify-between border-t border-zinc-200 px-6 py-4">
                    <p className="text-sm text-zinc-500">
                        Page <span className="font-medium text-zinc-900">{pageResponse ? pageResponse.page + 1 : 1}</span> sur <span className="font-medium text-zinc-900">{pageResponse?.totalPages || 1}</span>
                    </p>
                    <div className="flex items-center gap-2">
                        <button
                            type="button"
                            onClick={handlePreviousPage}
                            disabled={isLoading || currentPage === 0}
                            className="rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                            Précédent
                        </button>
                        <button
                            type="button"
                            onClick={handleNextPage}
                            disabled={isLoading || !pageResponse || pageResponse.last}
                            className="rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                            Suivant
                        </button>
                    </div>
                </div>
            </HmsCard>
        </div>
    );
}
