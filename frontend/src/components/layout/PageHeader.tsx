import type { ReactNode } from "react";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

interface PageHeaderProps {
    title: string;
    description?: string;
    /** Petit label en majuscules au-dessus du titre (ex: "CRÉATION", "CH-101"). */
    eyebrow?: string;
    /** Si fourni, affiche un bouton retour rond pointant vers ce lien. */
    backHref?: string;
    /** Actions alignées à droite (boutons). */
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
                                className="flex h-10 w-10 items-center justify-center rounded-full border border-zinc-200 bg-white text-zinc-600 transition hover:bg-zinc-50 hover:text-zinc-900"
                                aria-label="Retour"
                            >
                                <ArrowLeft className="h-5 w-5" />
                            </Link>
                        )}
                        {eyebrow && (
                            <span className="text-sm font-semibold uppercase tracking-wider text-zinc-400">
                                {eyebrow}
                            </span>
                        )}
                    </div>
                )}

                <div>
                    <h1 className="text-3xl font-bold tracking-tight text-zinc-950">{title}</h1>
                    {description && (
                        <p className="mt-2 max-w-2xl text-base leading-relaxed text-zinc-500">
                            {description}
                        </p>
                    )}
                </div>
            </div>

            {actions && <div className="flex shrink-0 items-center gap-3">{actions}</div>}
        </div>
    );
}
