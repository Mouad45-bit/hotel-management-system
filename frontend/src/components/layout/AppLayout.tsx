import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";

interface AppLayoutProps {
    children: ReactNode;
    title: string;
    description?: string;
}

export function AppLayout({ children, title, description }: AppLayoutProps) {
    return (
        <div className="min-h-screen bg-[var(--hms-page)]">
            <Sidebar />

            <div className="lg:pl-[280px]">
                <Topbar title={title} description={description} />

                <main className="px-5 py-8 sm:px-8 lg:px-12 lg:py-10">
                    <div className="mx-auto max-w-[1200px]">{children}</div>
                </main>
            </div>
        </div>
    );
}
