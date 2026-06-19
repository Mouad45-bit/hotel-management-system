import { HousekeepingTasksListClient } from "@/components/housekeeping/HousekeepingTasksListClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function HousekeepingTasksPage() {
    return (
        <AppLayout
            title="Tâches housekeeping"
            description="Liste, filtres et actions de nettoyage"
        >
            <HousekeepingTasksListClient />
        </AppLayout>
    );
}
