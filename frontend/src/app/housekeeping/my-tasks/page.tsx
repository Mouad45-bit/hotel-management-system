import { MyHousekeepingTasksClient } from "@/components/housekeeping/MyHousekeepingTasksClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function MyHousekeepingTasksPage() {
    return (
        <AppLayout>
            <MyHousekeepingTasksClient />
        </AppLayout>
    );
}
