'use client';

import { UserRole } from '@/types/user';

const ROLE_CONFIG: Record<UserRole, { label: string; className: string }> = {
    ADMIN: { label: 'Admin', className: 'bg-red-50 text-red-700 ring-red-200' },
    MANAGER: { label: 'Manager', className: 'bg-indigo-50 text-indigo-700 ring-indigo-200' },
    RECEPTIONIST: { label: 'Réceptionniste', className: 'bg-emerald-50 text-emerald-700 ring-emerald-200' },
    HOUSEKEEPING_AGENT: { label: 'Housekeeping', className: 'bg-amber-50 text-amber-700 ring-amber-200' },
    HR: { label: 'RH', className: 'bg-violet-50 text-violet-700 ring-violet-200' },
};

export function UserRoleBadge({ role }: { role: UserRole }) {
    const config = ROLE_CONFIG[role] ?? { label: role, className: 'bg-zinc-50 text-zinc-700 ring-zinc-200' };
    return (
        <span className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset ${config.className}`}>
            {config.label}
        </span>
    );
}
