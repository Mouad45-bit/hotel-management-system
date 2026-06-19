"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeftIcon, ExclamationTriangleIcon } from "@heroicons/react/24/outline";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingTaskActionPanel } from "@/components/housekeeping/HousekeepingTaskActionPanel";
import { HousekeepingTaskDetailHeader } from "@/components/housekeeping/HousekeepingTaskDetailHeader";
import { HousekeepingTaskInfoCards } from "@/components/housekeeping/HousekeepingTaskInfoCards";
import { HousekeepingTaskTimeline } from "@/components/housekeeping/HousekeepingTaskTimeline";
import { getHousekeepingTaskById } from "@/services/housekeepingApi";
import type { HousekeepingTask } from "@/types/housekeeping";

interface HousekeepingTaskDetailClientProps {
    taskId: number;
}

export function HousekeepingTaskDetailClient({
    taskId,
}: HousekeepingTaskDetailClientProps) {
    const [task, setTask] = useState<HousekeepingTask | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    async function loadTask() {
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
        void loadTask();
    }, [taskId]);

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
                    href="/housekeeping/tasks"
                    className="inline-flex items-center gap-2 text-sm font-semibold text-zinc-700 transition hover:text-zinc-950"
                >
                    <ArrowLeftIcon className="h-4 w-4" />
                    Retour aux tâches
                </Link>
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0" />
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
                    <HousekeepingTaskInfoCards task={task} />
                </div>
                <div className="space-y-6">
                    <HousekeepingTaskActionPanel task={task} onTaskUpdated={setTask} />
                    <HousekeepingTaskTimeline task={task} />
                </div>
            </div>
        </div>
    );
}
