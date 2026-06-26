import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { PageHeader } from "./PageHeader";

interface AppLayoutProps {
    children: ReactNode;
    title?: string;
    description?: string;
}

export function AppLayout({ children, title, description }: AppLayoutProps) {
    return (
        <div className="min-h-screen bg-[var(--hms-page)]">
            <Sidebar />

            <div className="lg:pl-64">
                <Topbar />

                <main className="mx-auto max-w-7xl space-y-8 px-6 py-8">
                    {title && <PageHeader title={title} description={description} />}
                    {children}
                </main>
            </div>
        </div>
    );
}
