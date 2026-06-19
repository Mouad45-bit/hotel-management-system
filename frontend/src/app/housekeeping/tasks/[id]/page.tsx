import { HousekeepingTaskDetailClient } from "@/components/housekeeping/HousekeepingTaskDetailClient";
import { AppLayout } from "@/components/layout/AppLayout";

interface HousekeepingTaskDetailPageProps {
    params: Promise<{
        id: string;
    }>;
}

export default async function HousekeepingTaskDetailPage({
    params,
}: HousekeepingTaskDetailPageProps) {
    const { id } = await params;
    const taskId = Number(id);

    return (
        <AppLayout
            title="Détail tâche"
            description="Consultation et actions housekeeping"
        >
            <HousekeepingTaskDetailClient taskId={taskId} />
        </AppLayout>
    );
}
