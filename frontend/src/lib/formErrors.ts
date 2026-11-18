export function extractFormErrors<TField extends string>(
    issues: { path: PropertyKey[]; message: string }[]
): Partial<Record<TField, string>> {
    const errors: Partial<Record<TField, string>> = {};

    issues.forEach((issue) => {
        const field = issue.path[0];

        if (typeof field === "string") {
            errors[field as TField] = issue.message;
        }
    });

    return errors;
}
