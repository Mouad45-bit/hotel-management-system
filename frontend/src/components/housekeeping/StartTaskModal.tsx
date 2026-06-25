"use client";

import { Play } from "lucide-react";
import { HousekeepingActionModal } from "@/components/housekeeping/HousekeepingActionModal";
import type { HousekeepingTask } from "@/types/housekeeping";

interface StartTaskModalProps {
    open: boolean;
    task: HousekeepingTask;
    submitting?: boolean;
    onClose: () => void;
    onConfirm: () => void;
}

export function StartTaskModal({
    open,
    task,
    submitting = false,
    onClose,
    onConfirm,
}: StartTaskModalProps) {
    return (
        <HousekeepingActionModal
            open={open}
            title="Démarrer la tâche"
            description="Cette action passe la tâche de À faire à En cours. La chambre ne doit pas être vendue comme disponible."
            icon={Play}
            iconClassName="bg-amber-50 text-amber-700"
            confirmLabel="Démarrer"
            submitting={submitting}
            onClose={onClose}
            onConfirm={onConfirm}
        >
            <div className="rounded-2xl border border-orange-200 bg-orange-50 p-4 text-sm leading-6 text-orange-800">
                Chambre {task.roomNumber} · l’agent assigné est {task.assignedAgentName ?? "non renseigné"}.
            </div>
        </HousekeepingActionModal>
    );
}
