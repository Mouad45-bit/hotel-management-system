import { HousekeepingDashboardClient } from "@/components/housekeeping/HousekeepingDashboardClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function HousekeepingPage() {
    return (
        <AppLayout
            title="Housekeeping"
            description="Vue opérationnelle du jour"
        >
            <HousekeepingDashboardClient />
        </AppLayout>
    );
}
