"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
    ArrowLeft,
    CircleCheckBig,
    Eye,
    EyeOff,
    TriangleAlert,
    UserRound,
} from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { HmsInput, HmsSelect } from "@/components/hms/HmsField";
import { DepartmentBadge } from "@/components/staff/StaffBadges";
import {
    createEmployee,
    getEmployeeById,
    updateEmployee,
} from "@/services/staffApi";
import { staffFormSchema, type StaffFormValues } from "@/schemas/staff.schema";
import {
    DEPARTMENT_LABELS,
    DEPARTMENTS,
    type Department,
    type Employee,
} from "@/types/staff";
import { extractFormErrors } from "@/lib/formErrors";

interface StaffFormState {
    firstName: string;
    lastName: string;
    cin: string;
    email: string;
    phone: string;
    department: Department;
}

interface StaffAccountFormState {
    hasSystemAccount: boolean;
    username: string;
    initialPassword: string;
    newPassword: string;
}

interface StaffFormClientProps {
    mode: "create" | "edit";
    employeeId?: number;
}

const DEFAULT_FORM: StaffFormState = {
    firstName: "",
    lastName: "",
    cin: "",
    email: "",
    phone: "",
    department: "RECEPTION",
};

const DEFAULT_ACCOUNT_FORM: StaffAccountFormState = {
    hasSystemAccount: false,
    username: "",
    initialPassword: "",
    newPassword: "",
};

type StaffFormField = keyof StaffFormState;
type StaffAccountField = keyof StaffAccountFormState;

interface PasswordFieldProps {
    id: string;
    label: string;
    value: string;
    visible: boolean;
    error?: string;
    hint?: string;
    placeholder?: string;
    className?: string;
    onChange: (value: string) => void;
    onToggleVisibility: () => void;
}

function PasswordField({
    id,
    label,
    value,
    visible,
    error,
    hint,
    placeholder,
    className,
    onChange,
    onToggleVisibility,
}: PasswordFieldProps) {
    return (
        <div className={className}>
            <label
                htmlFor={id}
                className="text-xs font-semibold text-[var(--hms-text-muted)]"
            >
                {label}
            </label>

            <div className="relative mt-2">
                <input
                    id={id}
                    type={visible ? "text" : "password"}
                    value={value}
                    onChange={(event) => onChange(event.target.value)}
                    placeholder={placeholder}
                    aria-invalid={Boolean(error)}
                    className="h-12 w-full rounded-xl border border-[var(--hms-border)] bg-white px-4 pr-12 text-sm text-[var(--hms-text)] outline-none transition-colors duration-150 placeholder:text-[rgba(13,9,7,0.38)] focus:border-[var(--hms-focus)] focus:ring-2 focus:ring-[rgba(25,25,112,0.12)]"
                />

                <button
                    type="button"
                    onClick={onToggleVisibility}
                    className="absolute right-2 top-1/2 inline-flex h-9 w-9 -translate-y-1/2 cursor-pointer items-center justify-center rounded-xl text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)]"
                    aria-label={visible ? "Masquer le mot de passe" : "Afficher le mot de passe"}
                >
                    {visible ? (
                        <EyeOff aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                    ) : (
                        <Eye aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                    )}
                </button>
            </div>

            {hint && !error && (
                <p className="mt-2 text-xs text-[var(--hms-text-muted)]">{hint}</p>
            )}

            {error && <p className="mt-2 text-xs text-red-600">{error}</p>}
        </div>
    );
}

function toFormState(employee: Employee): StaffFormState {
    return {
        firstName: employee.firstName,
        lastName: employee.lastName,
        cin: employee.cin,
        email: employee.email ?? "",
        phone: employee.phone ?? "",
        department: employee.department,
    };
}

export function StaffFormClient({ mode, employeeId }: StaffFormClientProps) {
    const router = useRouter();
    const isEdit = mode === "edit";

    const [form, setForm] = useState<StaffFormState>(DEFAULT_FORM);
    const [accountForm, setAccountForm] = useState<StaffAccountFormState>(DEFAULT_ACCOUNT_FORM);
    const [employee, setEmployee] = useState<Employee | null>(null);
    const [errors, setErrors] = useState<Partial<Record<StaffFormField, string>>>({});
    const [accountErrors, setAccountErrors] = useState<Partial<Record<StaffAccountField, string>>>({});
    const [showInitialPassword, setShowInitialPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(isEdit);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [successMessage, setSuccessMessage] = useState<string | null>(null);

    useEffect(() => {
        if (!isEdit || !employeeId) {
            return;
        }

        const id = employeeId;

        async function loadEmployee() {
            setIsLoading(true);
            setErrorMessage(null);

            try {
                const loadedEmployee = await getEmployeeById(id);
                setEmployee(loadedEmployee);
                setForm(toFormState(loadedEmployee));
            } catch (error) {
                setErrorMessage(error instanceof Error ? error.message : "Impossible de charger l’employé.");
            } finally {
                setIsLoading(false);
            }
        }

        void loadEmployee();
    }, [employeeId, isEdit]);

    function updateField<K extends keyof StaffFormState>(field: K, value: StaffFormState[K]) {
        setForm((current) => ({ ...current, [field]: value }));
    }

    function updateAccountField<K extends keyof StaffAccountFormState>(
        field: K,
        value: StaffAccountFormState[K]
    ) {
        setAccountForm((current) => ({ ...current, [field]: value }));
    }

    function toggleCreateAccountType() {
        setAccountForm((current) => {
            const hasSystemAccount = !current.hasSystemAccount;

            return {
                ...current,
                hasSystemAccount,
                username: hasSystemAccount ? current.username : "",
                initialPassword: "",
            };
        });
        setShowInitialPassword(false);
        setAccountErrors({});
    }

    async function handleSubmit() {
        setErrorMessage(null);
        setSuccessMessage(null);

        const validationResult = staffFormSchema.safeParse(form);
        const nextAccountErrors: Partial<Record<StaffAccountField, string>> = {};

        if (!validationResult.success) {
            setErrors(extractFormErrors<StaffFormField>(validationResult.error.issues));
        } else {
            setErrors({});
        }

        if (!isEdit && accountForm.hasSystemAccount) {
            if (!accountForm.username.trim()) {
                nextAccountErrors.username = "Le nom d’utilisateur est obligatoire pour un compte lié.";
            }

            if (!accountForm.initialPassword) {
                nextAccountErrors.initialPassword = "Le mot de passe initial est obligatoire pour un compte lié.";
            }
        }

        if (Object.keys(nextAccountErrors).length > 0) {
            setAccountErrors(nextAccountErrors);
            return;
        }

        if (!validationResult.success) {
            return;
        }

        setAccountErrors({});

        if (!isEdit && accountForm.hasSystemAccount) {
            setAccountForm((current) => ({ ...current, initialPassword: "" }));
            setShowInitialPassword(false);
            setErrorMessage("La création d’un compte système nécessite une API Auth absente du projet. La fiche employé n’a pas été créée.");
            return;
        }

        setIsSubmitting(true);

        try {
            const payload = validationResult.data as StaffFormValues;
            const savedEmployee = isEdit && employeeId
                ? await updateEmployee(employeeId, payload)
                : await createEmployee(payload);

            setSuccessMessage(isEdit ? "Les modifications ont été enregistrées." : "L’employé a été créé.");

            setAccountForm((current) => ({
                ...current,
                initialPassword: "",
            }));
            setShowInitialPassword(false);
            router.push(`/staff/${savedEmployee.id}`);
        } catch (error) {
            setErrorMessage(error instanceof Error ? error.message : "Impossible d’enregistrer l’employé.");
        } finally {
            setIsSubmitting(false);
        }
    }

    if (isLoading) {
        return (
            <div className="space-y-8">
                <HmsCard>
                    <div className="h-6 w-48 animate-pulse rounded-lg bg-slate-100" />
                    <div className="mt-4 h-10 w-80 animate-pulse rounded-lg bg-slate-100" />
                </HmsCard>
                <div className="grid gap-6 xl:grid-cols-2">
                    <HmsCard><div className="h-80 animate-pulse rounded-xl bg-slate-100" /></HmsCard>
                    <HmsCard><div className="h-80 animate-pulse rounded-xl bg-slate-100" /></HmsCard>
                </div>
            </div>
        );
    }

    const fullName = `${form.firstName} ${form.lastName}`.trim() || "Nouvel employé";

    return (
        <div className="space-y-8">
            <section>
                <Link
                    href={isEdit && employee ? `/staff/${employee.id}` : "/staff"}
                    className="inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl border border-[var(--hms-border)] bg-white px-3 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                >
                    <ArrowLeft aria-hidden="true" className="h-4 w-4" strokeWidth={1.8} />
                    Retour
                </Link>

                {isEdit && employee && (
                    <p className="mt-6 text-xs font-bold uppercase tracking-[0.18em] text-[var(--hms-text-muted)]">
                        Employé #{employee.id}
                    </p>
                )}

                <h2 className="mt-6 text-4xl font-extrabold tracking-tight text-[var(--hms-text)]">
                    {isEdit ? "Modifier l’employé" : "Ajouter un employé"}
                </h2>
                <p className="mt-4 max-w-3xl text-base leading-7 text-[var(--hms-text-muted)]">
                    Renseignez l’identité opérationnelle, le CIN et le département.
                    <br className="hidden md:block" /> Aucun mot de passe, rôle Auth ou salaire n’est demandé.
                </p>
            </section>

            {errorMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    <TriangleAlert aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                    <div>
                        <p className="font-semibold">Erreur</p>
                        <p className="mt-1">{errorMessage}</p>
                    </div>
                </div>
            )}

            {successMessage && (
                <div className="flex items-start gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">
                    <CircleCheckBig aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                    <div>
                        <p className="font-semibold">Enregistré</p>
                        <p className="mt-1">{successMessage}</p>
                    </div>
                </div>
            )}

            <div className="grid gap-6 xl:grid-cols-2">
                <HmsCard className="p-6">
                    <h3 className="text-lg font-bold text-[var(--hms-text)]">Informations employé</h3>
                    <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                        Les champs marqués d’un astérisque sont obligatoires.
                    </p>

                    <div className="mt-6 grid gap-5 md:grid-cols-2">
                        <HmsInput
                            id="staff-first-name"
                            label="Prénom *"
                            value={form.firstName}
                            onChange={(event) => updateField("firstName", event.target.value)}
                            error={errors.firstName}
                        />
                        <HmsInput
                            id="staff-last-name"
                            label="Nom *"
                            value={form.lastName}
                            onChange={(event) => updateField("lastName", event.target.value)}
                            error={errors.lastName}
                        />
                        <HmsInput
                            id="staff-cin"
                            label="CIN *"
                            value={form.cin}
                            onChange={(event) => updateField("cin", event.target.value)}
                            error={errors.cin}
                        />
                        <HmsSelect
                            id="staff-department"
                            label="Département *"
                            value={form.department}
                            onChange={(event) => updateField("department", event.target.value as Department)}
                            error={errors.department}
                        >
                            {DEPARTMENTS.map((department) => (
                                <option key={department} value={department}>
                                    {DEPARTMENT_LABELS[department]}
                                </option>
                            ))}
                        </HmsSelect>
                        <HmsInput
                            id="staff-email"
                            label="Email"
                            type="email"
                            value={form.email}
                            onChange={(event) => updateField("email", event.target.value)}
                            error={errors.email}
                            className="md:col-span-2"
                        />
                        <HmsInput
                            id="staff-phone"
                            label="Téléphone"
                            value={form.phone}
                            onChange={(event) => updateField("phone", event.target.value)}
                            error={errors.phone}
                            className="md:col-span-2"
                        />

                        {!isEdit && (
                            <div className="md:col-span-2">
                                <button
                                    type="button"
                                    role="switch"
                                    aria-checked={accountForm.hasSystemAccount}
                                    onClick={toggleCreateAccountType}
                                    className="flex w-full cursor-pointer items-center justify-between gap-4 rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4 text-left transition-colors hover:bg-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                >
                                    <span>
                                        <span className="block text-sm font-bold text-[var(--hms-text)]">
                                            Compte système lié
                                        </span>
                                        <span className="mt-1 block text-sm text-[var(--hms-text-muted)]">
                                            {accountForm.hasSystemAccount
                                                ? "Cet employé possède un compte système."
                                                : "Cet employé ne possède pas de compte système."}
                                        </span>
                                    </span>

                                    <span
                                        className={
                                            accountForm.hasSystemAccount
                                                ? "flex h-6 w-11 shrink-0 items-center rounded-full bg-[var(--hms-primary)] p-1 transition-colors"
                                                : "flex h-6 w-11 shrink-0 items-center rounded-full bg-slate-300 p-1 transition-colors"
                                        }
                                    >
                                        <span
                                            className={
                                                accountForm.hasSystemAccount
                                                    ? "h-4 w-4 translate-x-5 rounded-full bg-white transition-transform"
                                                    : "h-4 w-4 translate-x-0 rounded-full bg-white transition-transform"
                                            }
                                        />
                                    </span>
                                </button>
                            </div>
                        )}

                        {!isEdit && accountForm.hasSystemAccount && (
                            <>
                                <HmsInput
                                    id="staff-account-username"
                                    label="Nom d’utilisateur *"
                                    value={accountForm.username}
                                    onChange={(event) => updateAccountField("username", event.target.value)}
                                    error={accountErrors.username}
                                />
                                <PasswordField
                                    id="staff-account-initial-password"
                                    label="Mot de passe initial *"
                                    value={accountForm.initialPassword}
                                    visible={showInitialPassword}
                                    error={accountErrors.initialPassword}
                                    onChange={(value) => updateAccountField("initialPassword", value)}
                                    onToggleVisibility={() => setShowInitialPassword((current) => !current)}
                                />
                            </>
                        )}
                    </div>
                </HmsCard>

                <HmsCard className="p-6">
                    <h3 className="text-lg font-bold text-[var(--hms-text)]">Aperçu employé</h3>
                    <p className="mt-1 text-sm text-[var(--hms-text-muted)]">
                        Vérifiez l’identité opérationnelle avant enregistrement.
                    </p>

                    <div className="mt-6 rounded-2xl border border-[var(--hms-soft-border)] bg-slate-50 p-4">
                        <div className="flex items-start gap-3">
                            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-white text-[var(--hms-primary)] shadow-sm">
                                <UserRound aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                            </div>
                            <div className="min-w-0">
                                <p className="text-lg font-bold text-[var(--hms-text)]">{fullName}</p>
                                <p className="mt-1 text-sm text-[var(--hms-text-muted)]">CIN {form.cin || "à renseigner"}</p>
                                <div className="mt-3">
                                    <DepartmentBadge department={form.department} />
                                </div>
                            </div>
                        </div>
                    </div>

                    <dl className="mt-6 space-y-3 text-sm">
                        <div className="flex justify-between gap-4">
                            <dt className="text-[var(--hms-text-muted)]">Email</dt>
                            <dd className="font-semibold text-[var(--hms-text)]">{form.email || "Non renseigné"}</dd>
                        </div>
                        <div className="flex justify-between gap-4">
                            <dt className="text-[var(--hms-text-muted)]">Téléphone</dt>
                            <dd className="font-semibold text-[var(--hms-text)]">{form.phone || "Non renseigné"}</dd>
                        </div>
                    </dl>
                </HmsCard>
            </div>

            <HmsCard className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3 text-sm text-[var(--hms-text-muted)]">
                    <UserRound aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
                    {isEdit && employee ? `Employé #${employee.id}` : "Nouvel employé"}
                </div>
                <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
                    <Link
                        href={isEdit && employee ? `/staff/${employee.id}` : "/staff"}
                        className="inline-flex min-h-12 cursor-pointer items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white px-4 py-2 text-sm font-semibold text-[var(--hms-text)] transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                    >
                        Annuler
                    </Link>
                    <HmsButton type="button" onClick={() => void handleSubmit()} disabled={isSubmitting}>
                        {isSubmitting ? "Enregistrement..." : isEdit ? "Enregistrer les modifications" : "Créer l’employé"}
                    </HmsButton>
                </div>
            </HmsCard>
        </div>
    );
}
