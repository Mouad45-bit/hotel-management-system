import type {
    InputHTMLAttributes,
    ReactNode,
    SelectHTMLAttributes,
    TextareaHTMLAttributes,
} from "react";
import { cn } from "@/lib/utils";

interface BaseFieldProps {
    id: string;
    label: string;
    error?: string;
    hint?: ReactNode;
    className?: string;
}

const controlClassName =
    "mt-2 w-full rounded-xl border border-[var(--hms-border)] bg-white px-4 text-sm text-[var(--hms-text)] outline-none transition-colors duration-150 placeholder:text-[rgba(13,9,7,0.38)] focus:border-[var(--hms-focus)] focus:ring-2 focus:ring-[rgba(25,25,112,0.12)] disabled:cursor-not-allowed disabled:bg-slate-50 disabled:text-[var(--hms-text-muted)]";

function FieldShell({
    id,
    label,
    error,
    hint,
    className,
    children,
}: BaseFieldProps & { children: ReactNode }) {
    return (
        <div className={className}>
            <label
                htmlFor={id}
                className="text-xs font-semibold text-[var(--hms-text-muted)]"
            >
                {label}
            </label>

            {children}

            {hint && !error && (
                <p className="mt-2 text-xs text-[var(--hms-text-muted)]">{hint}</p>
            )}

            {error && <p className="mt-2 text-xs text-red-600">{error}</p>}
        </div>
    );
}

export function HmsInput({
    id,
    label,
    error,
    hint,
    className,
    ...props
}: BaseFieldProps & InputHTMLAttributes<HTMLInputElement>) {
    return (
        <FieldShell id={id} label={label} error={error} hint={hint} className={className}>
            <input
                id={id}
                className={cn("h-12", controlClassName)}
                aria-invalid={Boolean(error)}
                {...props}
            />
        </FieldShell>
    );
}

export function HmsSelect({
    id,
    label,
    error,
    hint,
    className,
    children,
    ...props
}: BaseFieldProps & SelectHTMLAttributes<HTMLSelectElement>) {
    return (
        <FieldShell id={id} label={label} error={error} hint={hint} className={className}>
            <select
                id={id}
                className={cn("h-12 cursor-pointer", controlClassName)}
                aria-invalid={Boolean(error)}
                {...props}
            >
                {children}
            </select>
        </FieldShell>
    );
}

export function HmsTextarea({
    id,
    label,
    error,
    hint,
    className,
    ...props
}: BaseFieldProps & TextareaHTMLAttributes<HTMLTextAreaElement>) {
    return (
        <FieldShell id={id} label={label} error={error} hint={hint} className={className}>
            <textarea
                id={id}
                className={cn("min-h-28 py-3", controlClassName)}
                aria-invalid={Boolean(error)}
                {...props}
            />
        </FieldShell>
    );
}
