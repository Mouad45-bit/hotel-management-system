import { AppLayout } from "@/components/layout/AppLayout";
import { StaffDetailClient } from "@/components/staff/StaffDetailClient";

interface StaffDetailPageProps {
    params: Promise<{ id: string }>;
}

export default async function StaffDetailPage({ params }: StaffDetailPageProps) {
    const { id } = await params;

    return (
        <AppLayout
            title="Détail employé"
            description="Identité, département, statut et lien utilisateur"
        >
            <StaffDetailClient employeeId={Number(id)} />
        </AppLayout>
    );
}
