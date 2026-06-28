"use client";

import { PageHeader } from "@/components/layout/PageHeader";
import type { HousekeepingTask } from "@/types/housekeeping";

interface HousekeepingTaskDetailHeaderProps {
    task: HousekeepingTask;
}

export function HousekeepingTaskDetailHeader({
    task,
}: HousekeepingTaskDetailHeaderProps) {
    return (
        <PageHeader
            backHref="/housekeeping/tasks"
            eyebrow={`Tâche #${task.id}`}
            title={`Chambre ${task.roomNumber}`}
            description="Consultez les informations, les priorités et l’avancement de cette tâche."
        />
    );
}
