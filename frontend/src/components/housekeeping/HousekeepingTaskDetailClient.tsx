"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft, TriangleAlert } from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingTaskActionPanel } from "@/components/housekeeping/HousekeepingTaskActionPanel";
import { HousekeepingTaskDetailHeader } from "@/components/housekeeping/HousekeepingTaskDetailHeader";
import { HousekeepingTaskInfoCards } from "@/components/housekeeping/HousekeepingTaskInfoCards";
import { HousekeepingTaskTimeline } from "@/components/housekeeping/HousekeepingTaskTimeline";
import { getHousekeepingTaskById } from "@/services/housekeepingApi";
import type { HousekeepingTask } from "@/types/housekeeping";
import { useAuth } from "@/contexts/AuthContext";
import { getEmployees } from "@/services/staffApi";

interface HousekeepingTaskDetailClientProps {
    taskId: number;
}

const DEMO_HOUSEKEEPING_AGENT_ID = 101;

export function HousekeepingTaskDetailClient({
    taskId,
}: HousekeepingTaskDetailClientProps) {
    const { user } = useAuth();
    const router = useRouter();
    const [task, setTask] = useState<HousekeepingTask | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [agentId, setAgentId] = useState<number | null>(null);

    useEffect(() => {
        if (!user || user.role !== "HOUSEKEEPING_AGENT") {
            setAgentId(null);
            return;
        }

        getEmployees({ page: 0, size: 1000 })
            .then((employeesPage) => {
                const linkedEmployee = employeesPage.content.find(
                    (employee) => employee.authUserId === user.id
                );
                setAgentId(linkedEmployee?.id ?? DEMO_HOUSEKEEPING_AGENT_ID);
            })
            .catch(() => setAgentId(DEMO_HOUSEKEEPING_AGENT_ID));
    }, [user]);

    async function loadTask() {
        if (user?.role === "HOUSEKEEPING_AGENT" && !agentId) {
            setIsLoading(true);
            return;
        }

        if (!Number.isFinite(taskId) || taskId <= 0) {
            setTask(null);
            setErrorMessage("Identifiant de tâche invalide.");
            setIsLoading(false);
            return;
        }

        setIsLoading(true);
        setErrorMessage(null);

        try {
            const loadedTask = await getHousekeepingTaskById(taskId);
            if (
                user?.role === "HOUSEKEEPING_AGENT" &&
                agentId &&
                loadedTask.assignedAgentId !== agentId
            ) {
                router.replace("/housekeeping/my-tasks?unauthorized=1");
                return;
            }
            setTask(loadedTask);
        } catch (error) {
            setErrorMessage(
                error instanceof Error
                    ? error.message
                    : "Impossible de charger la tâche housekeeping."
            );
        } finally {
            setIsLoading(false);
        }
    }

    useEffect(() => {
        const timeoutId = window.setTimeout(() => {
            void loadTask();
        }, 0);

        return () => window.clearTimeout(timeoutId);
    }, [agentId, router, taskId, user?.role]);

    if (isLoading) {
        return (
            <div className="space-y-6">
                <HmsCard>
                    <div className="h-6 w-48 animate-pulse rounded-lg bg-zinc-100" />
                    <div className="mt-4 h-10 w-80 animate-pulse rounded-lg bg-zinc-100" />
                </HmsCard>
                <div className="grid gap-6 xl:grid-cols-[1fr_380px]">
                    <HmsCard>
                        <div className="h-72 animate-pulse rounded-xl bg-zinc-100" />
                    </HmsCard>
                    <HmsCard>
                        <div className="h-72 animate-pulse rounded-xl bg-zinc-100" />
                    </HmsCard>
                </div>
            </div>
        );
    }

    if (errorMessage || !task) {
        return (
            <div className="space-y-6">
                <Link
                    href={user?.role === "HOUSEKEEPING_AGENT" ? "/housekeeping/my-tasks" : "/housekeeping/tasks"}
                    className="inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-3 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                >
                    <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                    Retour aux tâches
                </Link>
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                    <div>
                        <p className="font-semibold">Tâche introuvable</p>
                        <p className="mt-1">
                            {errorMessage ?? "Impossible d’afficher cette tâche."}
                        </p>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <HousekeepingTaskDetailHeader task={task} />
            <div className="grid gap-6 xl:grid-cols-[1fr_380px]">
                <div className="space-y-6">
                    <HousekeepingTaskInfoCards
                        task={task}
                        actions={(
                            <HousekeepingTaskActionPanel
                                task={task}
                                onTaskUpdated={setTask}
                            />
                        )}
                    />
                </div>
                <div className="space-y-6">
                    <HousekeepingTaskTimeline task={task} />
                </div>
            </div>
        </div>
    );
}
