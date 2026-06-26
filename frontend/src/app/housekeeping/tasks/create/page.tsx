import { HousekeepingTaskCreateClient } from "@/components/housekeeping/HousekeepingTaskCreateClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function CreateHousekeepingTaskPage() {
    return (
        <AppLayout
            title="Créer une tâche"
            description="Création manuelle d'une tâche housekeeping"
        >
            <HousekeepingTaskCreateClient />
        </AppLayout>
    );
}
