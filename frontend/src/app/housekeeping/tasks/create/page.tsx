import { HousekeepingTaskCreateClient } from "@/components/housekeeping/HousekeepingTaskCreateClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function CreateHousekeepingTaskPage() {
    return (
        <AppLayout>
            <HousekeepingTaskCreateClient />
        </AppLayout>
    );
}
