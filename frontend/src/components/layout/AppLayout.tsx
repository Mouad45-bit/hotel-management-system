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
        <div className="min-h-screen bg-zinc-50">
            <Sidebar />

            <div className="lg:pl-64">
                <Topbar title={title} description={description} />

                <main className="p-6">{children}</main>
            </div>
        </div>
    );
}
