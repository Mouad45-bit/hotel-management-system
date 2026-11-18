import type { ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

interface HmsButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
    variant?: "primary" | "secondary" | "danger" | "icon";
}

export function HmsButton
({
     className,
     variant = "primary",
     ...props
}: HmsButtonProps) {
    return (
        <button
            className={cn(
                "inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-55",
                variant === "primary" && "bg-[var(--hms-primary)] text-white hover:bg-[var(--hms-primary-hover)] active:bg-[var(--hms-primary-active)]",
                variant === "secondary" &&
                "border border-[var(--hms-border)] bg-white text-[var(--hms-text)] hover:bg-slate-50",
                variant === "danger" && "bg-red-600 text-white hover:bg-red-700 active:bg-red-800",
                variant === "icon" && "min-h-11 w-11 border border-[var(--hms-border)] bg-white p-0 text-[var(--hms-text-muted)] hover:bg-slate-50 hover:text-[var(--hms-text)]",
                className
            )}
            {...props}
        />
    );
}
