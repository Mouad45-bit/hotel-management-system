import type { ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

interface HmsButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
    variant?: "primary" | "secondary" | "danger";
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
                "inline-flex items-center justify-center rounded-xl px-4 py-2 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-60",
                variant === "primary" && "bg-stone-900 text-white hover:bg-stone-800",
                variant === "secondary" &&
                "border border-zinc-200 bg-white text-zinc-700 hover:bg-zinc-50",
                variant === "danger" && "bg-red-600 text-white hover:bg-red-700",
                className
            )}
            {...props}
        />
    );
}
