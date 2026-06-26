"use client";

import { useEffect, useState } from "react";
import { UserPlus } from "lucide-react";
import { HousekeepingActionModal } from "@/components/housekeeping/HousekeepingActionModal";
import { HmsSelect } from "@/components/hms/HmsField";
import { assignHousekeepingTaskSchema } from "@/schemas/housekeeping.schema";
import type {
    AssignHousekeepingTaskRequest,
    HousekeepingAgentOption,
    HousekeepingTask,
} from "@/types/housekeeping";

interface AssignTaskModalProps {
    open: boolean;
    task: HousekeepingTask;
    agents: HousekeepingAgentOption[];
    submitting?: boolean;
    onClose: () => void;
    onConfirm: (request: AssignHousekeepingTaskRequest) => void;
}

export function AssignTaskModal({
    open,
    task,
    agents,
    submitting = false,
    onClose,
    onConfirm,
}: AssignTaskModalProps) {
    const [assignedAgentId, setAssignedAgentId] = useState("");
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    useEffect(() => {
        if (open) {
            const timeoutId = window.setTimeout(() => {
                const defaultAgent =
                    agents.find((agent) => agent.id === task.assignedAgentId) ?? agents[0];
                setAssignedAgentId(defaultAgent ? String(defaultAgent.id) : "");
                setErrorMessage(null);
            }, 0);

            return () => window.clearTimeout(timeoutId);
        }
    }, [agents, open, task.assignedAgentId]);

    function handleConfirm() {
        const validationResult = assignHousekeepingTaskSchema.safeParse({
            assignedAgentId,
        });

        if (!validationResult.success) {
            setErrorMessage(
                validationResult.error.issues[0]?.message ?? "Sélectionnez un agent."
            );
            return;
        }

        setErrorMessage(null);
        onConfirm(validationResult.data);
    }

    return (
        <HousekeepingActionModal
            open={open}
            title="Assigner la tâche"
            description="Choisissez un agent housekeeping actif. L’assignation ne change pas forcément le statut."
            icon={UserPlus}
            iconClassName="bg-blue-50 text-blue-700"
            confirmLabel="Assigner"
            submitting={submitting}
            confirmDisabled={!assignedAgentId || agents.length === 0}
            onClose={onClose}
            onConfirm={handleConfirm}
        >
            <div className="space-y-4">
                <div className="rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 text-sm text-[var(--hms-text)]">
                    Chambre {task.roomNumber} · Tâche #{task.id}
                </div>
                <HmsSelect
                    id="assign-housekeeping-agent"
                    label="Agent housekeeping"
                    value={assignedAgentId}
                    onChange={(event) => setAssignedAgentId(event.target.value)}
                    error={errorMessage ?? undefined}
                >
                    {agents.length === 0 && (
                        <option value="">Aucun agent actif</option>
                    )}
                    {agents.map((agent) => (
                        <option key={agent.id} value={agent.id}>
                            {agent.fullName}
                        </option>
                    ))}
                </HmsSelect>
            </div>
        </HousekeepingActionModal>
    );
}
