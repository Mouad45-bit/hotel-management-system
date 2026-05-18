interface TopbarProps {
    title: string;
    description?: string;
}

export function Topbar({ title, description }: TopbarProps) {
    return (
        <header className="border-b border-zinc-200 bg-white px-6 py-4">
            <div className="flex items-center justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-semibold tracking-tight text-zinc-950">
                        {title}
                    </h1>

                    {description && (
                        <p className="mt-1 text-sm text-zinc-500">{description}</p>
                    )}
                </div>

                <div className="rounded-full bg-stone-100 px-4 py-2 text-sm font-medium text-stone-700">
                    Démo locale
                </div>
            </div>
        </header>
    );
}
