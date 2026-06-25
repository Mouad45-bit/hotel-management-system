"use client";

import { useEffect, useState } from "react";
import {
    Ban,
    CheckCircle2,
    Play,
    UserPlus,
    type LucideIcon,
} from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { AssignTaskModal } from "@/components/housekeeping/AssignTaskModal";
import { CancelTaskModal } from "@/components/housekeeping/CancelTaskModal";
import { CompleteTaskModal } from "@/components/housekeeping/CompleteTaskModal";
import { HousekeepingStatusBadge } from "@/components/housekeeping/HousekeepingStatusBadge";
import { StartTaskModal } from "@/components/housekeeping/StartTaskModal";
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
import type {
    AssignHousekeepingTaskRequest,
    CancelHousekeepingTaskRequest,
    HousekeepingAgentOption,
    HousekeepingTask,
} from "@/types/housekeeping";

interface HousekeepingTaskActionPanelProps {
    task: HousekeepingTask;
    onTaskUpdated: (task: HousekeepingTask) => void;
}

type ActiveHousekeepingModal = "assign" | "start" | "complete" | "cancel" | null;

interface ActionCardProps {
    title: string;
    description: string;
    icon: LucideIcon;
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
        <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-white p-4">
            <div className="flex items-start gap-3">
                <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${iconClassName}`}>
                    <Icon aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                </div>
                <div className="flex-1">
                    <p className="text-sm font-bold text-[var(--hms-text)]">{title}</p>
                    <p className="mt-1 text-sm leading-6 text-[var(--hms-text-muted)]">
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
    const [agents, setAgents] = useState<HousekeepingAgentOption[]>([]);
    const [activeModal, setActiveModal] = useState<ActiveHousekeepingModal>(null);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    useEffect(() => {
        void getHousekeepingAgents()
            .then(setAgents)
            .catch(() => setAgents([]));
    }, []);

    function closeModal() {
        if (!isSubmitting) {
            setActiveModal(null);
        }
    }

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
            setActiveModal(null);
        } catch (error) {
            setErrorMessage(
                error instanceof Error ? error.message : "Action impossible sur cette tâche."
            );
        } finally {
            setIsSubmitting(false);
        }
    }

    async function handleAssign(request: AssignHousekeepingTaskRequest) {
        await runAction(
            () => assignHousekeepingTask(task.id, request),
            "La tâche a été assignée avec succès."
        );
    }

    async function handleCancel(request: CancelHousekeepingTaskRequest) {
        await runAction(
            () => cancelHousekeepingTask(task.id, request),
            "La tâche a été annulée."
        );
    }

    const assignAllowed = canAssignTask(task);
    const startAllowed = canStartTask(task);
    const completeAllowed = canCompleteTask(task);
    const cancelAllowed = canCancelTask(task);
    const hasActions = assignAllowed || startAllowed || completeAllowed || cancelAllowed;

    return (
        <>
            <HmsCard className="p-6">
                <div className="flex items-start justify-between gap-4">
                    <div>
                        <h3 className="text-lg font-bold text-[var(--hms-text)]">
                            Actions tâche
                        </h3>
                        <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                            Les actions métier sont confirmées dans des modals pour éviter les changements accidentels.
                        </p>
                    </div>
                    <HousekeepingStatusBadge status={task.status} />
                </div>

                {feedbackMessage && (
                    <div className="mt-4 flex items-start gap-2 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700">
                        <CheckCircle2 aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.8} />
                        {feedbackMessage}
                    </div>
                )}
                {errorMessage && (
                    <div className="mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                        {errorMessage}
                    </div>
                )}
                {!hasActions && (
                    <div className="mt-5 rounded-xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 text-sm text-[var(--hms-text-muted)]">
                        Aucune action métier n’est disponible pour ce statut final.
                    </div>
                )}

                <div className="mt-5 space-y-4">
                    {assignAllowed && (
                        <ActionCard
                            title="Assigner un agent"
                            description="Choisissez l’agent housekeeping responsable de cette tâche."
                            icon={UserPlus}
                            iconClassName="bg-blue-50 text-blue-700"
                            buttonLabel="Assigner"
                            disabled={isSubmitting}
                            onClick={() => setActiveModal("assign")}
                        />
                    )}
                    {startAllowed && (
                        <ActionCard
                            title="Démarrer la tâche"
                            description="La tâche passera de À faire à En cours."
                            icon={Play}
                            iconClassName="bg-amber-50 text-amber-700"
                            buttonLabel="Démarrer"
                            disabled={isSubmitting}
                            onClick={() => setActiveModal("start")}
                        />
                    )}
                    {completeAllowed && (
                        <ActionCard
                            title="Terminer la tâche"
                            description="La tâche passera à Terminée et pourra remettre la chambre en AVAILABLE."
                            icon={CheckCircle2}
                            iconClassName="bg-emerald-50 text-emerald-700"
                            buttonLabel="Terminer"
                            disabled={isSubmitting}
                            onClick={() => setActiveModal("complete")}
                        />
                    )}
                    {cancelAllowed && (
                        <ActionCard
                            title="Annuler la tâche"
                            description="La tâche passera à Annulée avec un motif obligatoire."
                            icon={Ban}
                            iconClassName="bg-red-50 text-red-700"
                            buttonLabel="Annuler"
                            danger
                            disabled={isSubmitting}
                            onClick={() => setActiveModal("cancel")}
                        />
                    )}
                </div>
            </HmsCard>

            <AssignTaskModal
                open={activeModal === "assign"}
                task={task}
                agents={agents}
                submitting={isSubmitting}
                onClose={closeModal}
                onConfirm={(request) => void handleAssign(request)}
            />
            <StartTaskModal
                open={activeModal === "start"}
                task={task}
                submitting={isSubmitting}
                onClose={closeModal}
                onConfirm={() =>
                    void runAction(
                        () => startHousekeepingTask(task.id),
                        "La tâche a été démarrée."
                    )
                }
            />
            <CompleteTaskModal
                open={activeModal === "complete"}
                task={task}
                submitting={isSubmitting}
                onClose={closeModal}
                onConfirm={() =>
                    void runAction(
                        () => completeHousekeepingTask(task.id),
                        "La tâche a été terminée."
                    )
                }
            />
            <CancelTaskModal
                open={activeModal === "cancel"}
                task={task}
                submitting={isSubmitting}
                onClose={closeModal}
                onConfirm={(request) => void handleCancel(request)}
            />
        </>
    );
}
