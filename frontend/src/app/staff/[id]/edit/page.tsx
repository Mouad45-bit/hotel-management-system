import { AppLayout } from "@/components/layout/AppLayout";
import { StaffFormClient } from "@/components/staff/StaffFormClient";

interface EditStaffPageProps {
    params: Promise<{ id: string }>;
}

export default async function EditStaffPage({ params }: EditStaffPageProps) {
    const { id } = await params;

    return (
        <AppLayout>
            <StaffFormClient mode="edit" employeeId={Number(id)} />
        </AppLayout>
    );
}
