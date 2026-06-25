"use client";

import { CheckCircle2 } from "lucide-react";
import { HousekeepingActionModal } from "@/components/housekeeping/HousekeepingActionModal";
import type { HousekeepingTask } from "@/types/housekeeping";

interface CompleteTaskModalProps {
    open: boolean;
    task: HousekeepingTask;
    submitting?: boolean;
    onClose: () => void;
    onConfirm: () => void;
}

export function CompleteTaskModal({
    open,
    task,
    submitting = false,
    onClose,
    onConfirm,
}: CompleteTaskModalProps) {
    return (
        <HousekeepingActionModal
            open={open}
            title="Terminer la tâche"
            description="Cette action passe la tâche de En cours à Terminée et peut remettre la chambre en AVAILABLE."
            icon={CheckCircle2}
            iconClassName="bg-emerald-50 text-emerald-700"
            confirmLabel="Terminer"
            submitting={submitting}
            onClose={onClose}
            onConfirm={onConfirm}
        >
            <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm leading-6 text-emerald-800">
                Confirmez que la chambre {task.roomNumber} est prête après nettoyage ou inspection.
            </div>
        </HousekeepingActionModal>
    );
}
