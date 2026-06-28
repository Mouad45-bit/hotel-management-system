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
import { HmsButton } from "@/components/hms/HmsButton";
import { PageHeader } from "@/components/layout/PageHeader";
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
            <PageHeader
                title="Housekeeping"
                description="Suivez les chambres à nettoyer, les priorités du jour et les tâches à affecter avant remise en vente."
                actions={
                    <>
                        <Link href="/housekeeping/my-tasks">
                            <HmsButton variant="secondary">
                                <UserRoundCheck aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                Mes tâches
                            </HmsButton>
                        </Link>
                        <Link href="/housekeeping/tasks">
                            <HmsButton variant="secondary">
                                <ClipboardList aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                Liste des tâches
                            </HmsButton>
                        </Link>
                        <Link href="/housekeeping/tasks/create">
                            <HmsButton>
                                <Plus aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                                Créer une tâche
                            </HmsButton>
                        </Link>
                    </>
                }
            />

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
