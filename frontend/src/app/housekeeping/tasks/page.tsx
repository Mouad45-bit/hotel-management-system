import { HousekeepingTasksListClient } from "@/components/housekeeping/HousekeepingTasksListClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function HousekeepingTasksPage() {
    return (
        <AppLayout>
            <HousekeepingTasksListClient />
        </AppLayout>
    );
}
