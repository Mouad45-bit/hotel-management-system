"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    ArrowLeft,
    Plus,
    RefreshCw,
    TriangleAlert,
} from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
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

function formatTaskCount(count: number, singularSuffix: string, pluralSuffix = `${singularSuffix}s`) {
    return `${count} ${count > 1 ? "tâches" : "tâche"} ${count > 1 ? pluralSuffix : singularSuffix}`;
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
                        <h2 className="text-4xl font-extrabold tracking-tight text-[var(--hms-text)]">
                            Tâches housekeeping
                        </h2>

                        <p className="mt-4 max-w-3xl text-base leading-7 text-[var(--hms-text-muted)]">
                            Suivez les tâches liées aux chambres, leur priorité, leur agent et leur statut opérationnel.
                        </p>
                    </div>

                    <Link
                        href="/housekeeping/tasks/create"
                        className="inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl bg-[var(--hms-primary)] px-5 py-3 text-sm font-semibold text-white transition-colors hover:bg-[var(--hms-primary-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                    >
                        <Plus aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                        Créer une tâche
                    </Link>
                </div>
            </section>

            <HousekeepingStatsCards stats={stats} loading={isLoading} />

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
                            {pageResponse
                                ? formatTaskCount(pageResponse.totalElements, "trouvée")
                                : "Chargement des tâches"}
                        </p>
                    </div>

                    <div className="flex items-center gap-1.5">
                        <HmsButton
                            type="button"
                            variant="secondary"
                            onClick={() => void loadTasks(filters, currentPage)}
                            disabled={isLoading}
                        >
                            <RefreshCw aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                            Actualiser
                        </HmsButton>

                        <HousekeepingTaskFilters
                            filters={filters}
                            errors={filterErrors}
                            onApply={handleApplyFilters}
                        />
                    </div>
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

                <div className="flex items-center justify-between border-t border-[var(--hms-soft-border)] px-6 py-5">
                    <p className="text-sm text-[var(--hms-text-muted)]">
                        Page <span className="font-medium text-[var(--hms-text)]">{pageResponse ? pageResponse.page + 1 : 1}</span> sur <span className="font-medium text-[var(--hms-text)]">{pageResponse?.totalPages || 1}</span>
                    </p>

                    <div className="flex items-center gap-2">
                        <HmsButton
                            type="button"
                            variant="secondary"
                            onClick={handlePreviousPage}
                            disabled={isLoading || currentPage === 0}
                            className="min-h-10 px-3"
                        >
                            Précédent
                        </HmsButton>

                        <HmsButton
                            type="button"
                            variant="secondary"
                            onClick={handleNextPage}
                            disabled={isLoading || !pageResponse || pageResponse.last}
                            className="min-h-10 px-3"
                        >
                            Suivant
                        </HmsButton>
                    </div>
                </div>
            </HmsCard>
        </div>
    );
}
