import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface HmsCardProps {
    children: ReactNode;
    className?: string;
}

export function HmsCard({ children, className }: HmsCardProps) {
    return (
        <div
            className={cn(
                "rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm",
                className
            )}
        >
            {children}
        </div>
    );
}
