"use client";

import { useState, type ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";

interface AppLayoutProps {
    children: ReactNode;
    title: string;
    description?: string;
}

export function AppLayout({ children, title, description }: AppLayoutProps) {
    const [collapsed, setCollapsed] = useState(false);

    return (
        <div className="min-h-screen bg-zinc-50">
            <Sidebar
                collapsed={collapsed}
                onToggle={() => setCollapsed(prev => !prev)}
            />

            <div
                className={`transition-all duration-300 ${
                    collapsed ? "lg:pl-20" : "lg:pl-64"
                }`}
            >
                <Topbar title={title} description={description} />
                <main className="p-6">{children}</main>
            </div>
        </div>
    );
}
