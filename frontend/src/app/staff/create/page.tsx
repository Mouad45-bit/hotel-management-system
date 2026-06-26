import { AppLayout } from "@/components/layout/AppLayout";
import { StaffFormClient } from "@/components/staff/StaffFormClient";

export default function CreateStaffPage() {
    return (
        <AppLayout
            title="Ajouter un employé"
            description="Créer une fiche personnel opérationnelle"
        >
            <StaffFormClient mode="create" />
        </AppLayout>
    );
}
