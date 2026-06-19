"use client";

import { useState } from "react";
import {
    CheckCircleIcon,
    NoSymbolIcon,
    PlayIcon,
    UserPlusIcon,
} from "@heroicons/react/24/outline";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { HousekeepingStatusBadge } from "@/components/housekeeping/HousekeepingStatusBadge";
import {
    canAssignTask,
    canCancelTask,
    canCompleteTask,
    canStartTask,
} from "@/lib/housekeepingHelpers";
import {
    assignHousekeepingTask,
    cancelHousekeepingTask,
    completeHousekeepingTask,
    getHousekeepingAgents,
    startHousekeepingTask,
} from "@/services/housekeepingApi";
import type { HousekeepingTask } from "@/types/housekeeping";

interface HousekeepingTaskActionPanelProps {
    task: HousekeepingTask;
    onTaskUpdated: (task: HousekeepingTask) => void;
}

interface ActionCardProps {
    title: string;
    description: string;
    icon: typeof UserPlusIcon;
    iconClassName: string;
    buttonLabel: string;
    danger?: boolean;
    disabled?: boolean;
    onClick: () => void;
}

function ActionCard({
    title,
    description,
    icon: Icon,
    iconClassName,
    buttonLabel,
    danger = false,
    disabled = false,
    onClick,
}: ActionCardProps) {
    return (
        <div className="rounded-2xl border border-zinc-200 p-4">
            <div className="flex items-start gap-3">
                <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${iconClassName}`}>
                    <Icon className="h-5 w-5" />
                </div>
                <div className="flex-1">
                    <p className="text-sm font-semibold text-zinc-950">{title}</p>
                    <p className="mt-1 text-sm leading-6 text-zinc-500">
                        {description}
                    </p>
                    <div className="mt-4">
                        <HmsButton
                            type="button"
                            variant={danger ? "danger" : "secondary"}
                            disabled={disabled}
                            onClick={onClick}
                        >
                            {buttonLabel}
                        </HmsButton>
                    </div>
                </div>
            </div>
        </div>
    );
}

export function HousekeepingTaskActionPanel({
    task,
    onTaskUpdated,
}: HousekeepingTaskActionPanelProps) {
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    async function runAction(
        callback: () => Promise<HousekeepingTask>,
        successMessage: string
    ) {
        setIsSubmitting(true);
        setFeedbackMessage(null);
        setErrorMessage(null);

        try {
            const updatedTask = await callback();
            onTaskUpdated(updatedTask);
            setFeedbackMessage(successMessage);
        } catch (error) {
            setErrorMessage(
                error instanceof Error ? error.message : "Action impossible sur cette tâche."
            );
        } finally {
            setIsSubmitting(false);
        }
    }

    async function handleAssign() {
        const agents = await getHousekeepingAgents();
        const fallbackAgent = agents.find((agent) => agent.id !== task.assignedAgentId) ?? agents[0];

        if (!fallbackAgent) {
            setErrorMessage("Aucun agent actif disponible pour l’assignation.");
            return;
        }

        await runAction(
            () => assignHousekeepingTask(task.id, { assignedAgentId: fallbackAgent.id }),
            `La tâche a été assignée à ${fallbackAgent.fullName}.`
        );
    }

    const assignAllowed = canAssignTask(task);
    const startAllowed = canStartTask(task);
    const completeAllowed = canCompleteTask(task);
    const cancelAllowed = canCancelTask(task);
    const hasActions = assignAllowed || startAllowed || completeAllowed || cancelAllowed;

    return (
        <HmsCard>
            <div className="flex items-start justify-between gap-4">
                <div>
                    <h3 className="text-sm font-semibold text-zinc-950">
                        Actions tâche
                    </h3>
                    <p className="mt-1 text-sm text-zinc-500">
                        Les actions disponibles respectent les transitions de statut V1.
                    </p>
                </div>
                <HousekeepingStatusBadge status={task.status} />
            </div>

            {feedbackMessage && (
                <div className="mt-4 flex items-start gap-2 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700">
                    <CheckCircleIcon className="mt-0.5 h-4 w-4 shrink-0" />
                    {feedbackMessage}
                </div>
            )}
            {errorMessage && (
                <div className="mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                    {errorMessage}
                </div>
            )}
            {!hasActions && (
                <div className="mt-5 rounded-xl border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-500">
                    Aucune action métier n’est disponible pour ce statut final.
                </div>
            )}

            <div className="mt-5 space-y-4">
                {assignAllowed && (
                    <ActionCard
                        title="Assigner un agent"
                        description="L’assignation référence un employé housekeeping existant et ne change pas forcément le statut."
                        icon={UserPlusIcon}
                        iconClassName="bg-blue-50 text-blue-700"
                        buttonLabel="Assigner"
                        disabled={isSubmitting}
                        onClick={() => void handleAssign()}
                    />
                )}
                {startAllowed && (
                    <ActionCard
                        title="Démarrer la tâche"
                        description="La tâche passera de À faire à En cours et la chambre sera en nettoyage."
                        icon={PlayIcon}
                        iconClassName="bg-amber-50 text-amber-700"
                        buttonLabel="Démarrer"
                        disabled={isSubmitting}
                        onClick={() =>
                            void runAction(
                                () => startHousekeepingTask(task.id),
                                "La tâche a été démarrée."
                            )
                        }
                    />
                )}
                {completeAllowed && (
                    <ActionCard
                        title="Terminer la tâche"
                        description="La tâche passera à Terminée et pourra remettre la chambre en AVAILABLE."
                        icon={CheckCircleIcon}
                        iconClassName="bg-emerald-50 text-emerald-700"
                        buttonLabel="Terminer"
                        disabled={isSubmitting}
                        onClick={() =>
                            void runAction(
                                () => completeHousekeepingTask(task.id),
                                "La tâche a été terminée."
                            )
                        }
                    />
                )}
                {cancelAllowed && (
                    <ActionCard
                        title="Annuler la tâche"
                        description="La tâche passera à Annulée avec un motif opérationnel."
                        icon={NoSymbolIcon}
                        iconClassName="bg-red-50 text-red-700"
                        buttonLabel="Annuler"
                        danger
                        disabled={isSubmitting}
                        onClick={() =>
                            void runAction(
                                () =>
                                    cancelHousekeepingTask(task.id, {
                                        reason: "Annulation opérationnelle depuis le détail.",
                                    }),
                                "La tâche a été annulée."
                            )
                        }
                    />
                )}
            </div>
        </HmsCard>
    );
}
