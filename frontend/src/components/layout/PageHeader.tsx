import type { ReactNode } from "react";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

interface PageHeaderProps {
    title: string;
    description?: string;
    eyebrow?: string;
    backHref?: string;
    actions?: ReactNode;
}

export function PageHeader({ title, description, eyebrow, backHref, actions }: PageHeaderProps) {
    return (
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="space-y-3">
                {(backHref || eyebrow) && (
                    <div className="flex items-center gap-3">
                        {backHref && (
                            <Link
                                href={backHref}
                                className="flex h-10 w-10 items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                aria-label="Retour"
                            >
                                <ArrowLeft className="h-5 w-5" strokeWidth={1.8} />
                            </Link>
                        )}
                        {eyebrow && (
                            <span className="text-sm font-semibold uppercase tracking-wider text-[var(--hms-text-muted)]">
                                {eyebrow}
                            </span>
                        )}
                    </div>
                )}

                <div>
                    <h1 className="text-3xl font-bold tracking-tight text-[var(--hms-text)]">{title}</h1>
                    {description && (
                        <p className="mt-2 max-w-2xl text-base leading-relaxed text-[var(--hms-text-muted)]">
                            {description}
                        </p>
                    )}
                </div>
            </div>

            {actions && <div className="flex shrink-0 items-center gap-3">{actions}</div>}
        </div>
    );
}
