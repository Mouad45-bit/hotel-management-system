import { Suspense } from "react";
import { HmsCard } from "@/components/hms/HmsCard";
import { AppLayout } from "@/components/layout/AppLayout";
import { StaffListClient } from "@/components/staff/StaffListClient";

function StaffListFallback() {
    return (
        <div className="space-y-8">
            <HmsCard>
                <div className="h-8 w-52 animate-pulse rounded-lg bg-slate-100" />
                <div className="mt-4 h-5 w-96 animate-pulse rounded-lg bg-slate-100" />
            </HmsCard>
            <HmsCard><div className="h-80 animate-pulse rounded-xl bg-slate-100" /></HmsCard>
        </div>
    );
}

export default function StaffPage() {
    return (
        <AppLayout
            title="Personnel"
            description="Gestion des employés et de leur statut opérationnel"
        >
            <Suspense fallback={<StaffListFallback />}>
                <StaffListClient />
            </Suspense>
        </AppLayout>
    );
}
