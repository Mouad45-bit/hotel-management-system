import { cn } from '@/lib/utils';

interface ClientStatusBadgeProps {
    active: boolean;
    className?: string;
}

export function ClientStatusBadge({ active, className }: ClientStatusBadgeProps) {
    return (
        <span
            className={cn(
                'inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset',
                active
                    ? 'bg-emerald-50 text-emerald-700 ring-emerald-200'
                    : 'bg-red-50 text-red-700 ring-red-200',
                className
            )}
        >
            {active ? 'Actif' : 'Inactif'}
        </span>
    );
}
