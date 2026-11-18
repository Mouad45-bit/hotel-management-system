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
                "rounded-[20px] border border-[var(--hms-soft-border)] bg-[var(--hms-surface)] p-6 shadow-[0_16px_40px_rgba(13,9,7,0.03)]",
                className
            )}
        >
            {children}
        </div>
    );
}
