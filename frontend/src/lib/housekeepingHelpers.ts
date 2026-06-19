import {
    HOUSEKEEPING_STATUS_LABELS,
    HOUSEKEEPING_TYPE_LABELS,
    PRIORITY_LABELS,
    type HousekeepingTask,
    type HousekeepingTaskStatus,
    type HousekeepingTaskType,
    type Priority,
} from "@/types/housekeeping";

export type HousekeepingAction =
    | "view"
    | "assign"
    | "start"
    | "complete"
    | "cancel";

export function formatHousekeepingDate(value?: string | null): string {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "—";
    }

    return new Intl.DateTimeFormat("fr-FR", {
        dateStyle: "medium",
    }).format(date);
}

export function formatHousekeepingDateTime(value?: string | null): string {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "—";
    }

    return new Intl.DateTimeFormat("fr-FR", {
        dateStyle: "medium",
        timeStyle: "short",
    }).format(date);
}

export function getHousekeepingStatusLabel(
    status: HousekeepingTaskStatus
): string {
    return HOUSEKEEPING_STATUS_LABELS[status];
}

export function getHousekeepingTypeLabel(type: HousekeepingTaskType): string {
    return HOUSEKEEPING_TYPE_LABELS[type];
}

export function getPriorityLabel(priority: Priority): string {
    return PRIORITY_LABELS[priority];
}

export function canAssignTask(task: HousekeepingTask): boolean {
    return task.status === "TODO" || task.status === "IN_PROGRESS";
}

export function canStartTask(task: HousekeepingTask): boolean {
    return task.status === "TODO";
}

export function canCompleteTask(task: HousekeepingTask): boolean {
    return task.status === "IN_PROGRESS";
}

export function canCancelTask(task: HousekeepingTask): boolean {
    return task.status === "TODO" || task.status === "IN_PROGRESS";
}

export function isFinalHousekeepingStatus(
    status: HousekeepingTaskStatus
): boolean {
    return status === "DONE" || status === "CANCELLED";
}

export function getAvailableHousekeepingActions(
    task: HousekeepingTask
): HousekeepingAction[] {
    const actions: HousekeepingAction[] = ["view"];

    if (canAssignTask(task)) {
        actions.push("assign");
    }

    if (canStartTask(task)) {
        actions.push("start");
    }

    if (canCompleteTask(task)) {
        actions.push("complete");
    }

    if (canCancelTask(task)) {
        actions.push("cancel");
    }

    return actions;
}

export function getHousekeepingActionLabel(action: HousekeepingAction): string {
    const labels: Record<HousekeepingAction, string> = {
        view: "Voir",
        assign: "Assigner",
        start: "Démarrer",
        complete: "Terminer",
        cancel: "Annuler",
    };

    return labels[action];
}
