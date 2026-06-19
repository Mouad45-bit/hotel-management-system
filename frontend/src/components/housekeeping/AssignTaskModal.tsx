"use client";

import { useEffect, useState } from "react";
import { UserPlusIcon } from "@heroicons/react/24/outline";
import { HousekeepingActionModal } from "@/components/housekeeping/HousekeepingActionModal";
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
            const defaultAgent =
                agents.find((agent) => agent.id === task.assignedAgentId) ?? agents[0];
            setAssignedAgentId(defaultAgent ? String(defaultAgent.id) : "");
            setErrorMessage(null);
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
            icon={UserPlusIcon}
            iconClassName="bg-blue-50 text-blue-700"
            confirmLabel="Assigner"
            submitting={submitting}
            confirmDisabled={!assignedAgentId || agents.length === 0}
            onClose={onClose}
            onConfirm={handleConfirm}
        >
            <div className="space-y-4">
                <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-700">
                    Chambre {task.roomNumber} · Tâche #{task.id}
                </div>
                <div>
                    <label className="text-xs font-medium text-zinc-600">
                        Agent housekeeping
                    </label>
                    <select
                        value={assignedAgentId}
                        onChange={(event) => setAssignedAgentId(event.target.value)}
                        className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                    >
                        {agents.length === 0 && (
                            <option value="">Aucun agent actif</option>
                        )}
                        {agents.map((agent) => (
                            <option key={agent.id} value={agent.id}>
                                {agent.fullName}
                            </option>
                        ))}
                    </select>
                    {errorMessage && (
                        <p className="mt-1 text-xs text-red-600">{errorMessage}</p>
                    )}
                </div>
            </div>
        </HousekeepingActionModal>
    );
}
