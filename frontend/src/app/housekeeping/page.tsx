import { HousekeepingDashboardClient } from "@/components/housekeeping/HousekeepingDashboardClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function HousekeepingPage() {
    return (
        <AppLayout>
            <HousekeepingDashboardClient />
        </AppLayout>
    );
}
