import { MyHousekeepingTasksClient } from "@/components/housekeeping/MyHousekeepingTasksClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function MyHousekeepingTasksPage() {
    return (
        <AppLayout
            title="My tasks"
            description="Tâches housekeeping de l'agent connecté"
        >
            <MyHousekeepingTasksClient agentId={101} />
        </AppLayout>
    );
}
