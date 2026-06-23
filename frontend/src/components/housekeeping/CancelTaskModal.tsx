"use client";

import { useEffect, useState } from "react";
import { NoSymbolIcon } from "@heroicons/react/24/outline";
import { HousekeepingActionModal } from "@/components/housekeeping/HousekeepingActionModal";
import { cancelHousekeepingTaskSchema } from "@/schemas/housekeeping.schema";
import type {
    CancelHousekeepingTaskRequest,
    HousekeepingTask,
} from "@/types/housekeeping";

interface CancelTaskModalProps {
    open: boolean;
    task: HousekeepingTask;
    submitting?: boolean;
    onClose: () => void;
    onConfirm: (request: CancelHousekeepingTaskRequest) => void;
}

export function CancelTaskModal({
    open,
    task,
    submitting = false,
    onClose,
    onConfirm,
}: CancelTaskModalProps) {
    const [reason, setReason] = useState("");
    const [errorMessage, setErrorMessage] = useState<string | null>(null);

    useEffect(() => {
        if (open) {
            const timeoutId = window.setTimeout(() => {
                setReason("");
                setErrorMessage(null);
            }, 0);

            return () => window.clearTimeout(timeoutId);
        }
    }, [open]);

    function handleConfirm() {
        const validationResult = cancelHousekeepingTaskSchema.safeParse({ reason });

        if (!validationResult.success) {
            setErrorMessage(
                validationResult.error.issues[0]?.message ?? "Le motif est obligatoire."
            );
            return;
        }

        setErrorMessage(null);
        onConfirm(validationResult.data);
    }

    return (
        <HousekeepingActionModal
            open={open}
            title="Annuler la tâche"
            description="Cette action passe la tâche à Annulée. Le motif est obligatoire."
            icon={NoSymbolIcon}
            iconClassName="bg-red-50 text-red-700"
            confirmLabel="Annuler la tâche"
            submitting={submitting}
            danger
            onClose={onClose}
            onConfirm={handleConfirm}
        >
            <div className="space-y-4">
                <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-800">
                    Chambre {task.roomNumber} · tâche #{task.id}
                </div>
                <div>
                    <label className="text-xs font-medium text-zinc-600">
                        Motif d’annulation
                    </label>
                    <textarea
                        value={reason}
                        onChange={(event) => setReason(event.target.value)}
                        rows={4}
                        placeholder="Exemple : chambre bloquée pour maintenance"
                        className="mt-1 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-stone-400 focus:ring-2 focus:ring-stone-100"
                    />
                    {errorMessage && (
                        <p className="mt-1 text-xs text-red-600">{errorMessage}</p>
                    )}
                </div>
            </div>
        </HousekeepingActionModal>
    );
}
