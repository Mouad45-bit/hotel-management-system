import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { PageHeader } from "./PageHeader";

interface AppLayoutProps {
    children: ReactNode;
    /**
     * En-tête de page optionnel. Les pages qui ont besoin d'un en-tête riche
     * (bouton retour, actions...) rendent elles-mêmes <PageHeader /> dans children.
     */
    title?: string;
    description?: string;
}

export function AppLayout({ children, title, description }: AppLayoutProps) {
    return (
        <div className="min-h-screen bg-zinc-50">
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
