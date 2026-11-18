import { AppLayout } from "@/components/layout/AppLayout";
import { StaffFormClient } from "@/components/staff/StaffFormClient";

export default function CreateStaffPage() {
    return (
        <AppLayout>
            <StaffFormClient mode="create" />
        </AppLayout>
    );
}
