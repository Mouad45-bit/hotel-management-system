import { z } from "zod";

export const clientSchema = z.object({
    firstName: z.string().min(1, "Le prénom est obligatoire"),
    lastName: z.string().min(1, "Le nom est obligatoire"),
    email: z.string().email("L'email doit être valide").optional().or(z.literal("")),
    phone: z.string().optional().or(z.literal("")),
    cin: z.string().optional().or(z.literal("")),
    passportNumber: z.string().optional().or(z.literal("")),
    nationality: z.string().optional().or(z.literal("")),
    address: z.string().optional().or(z.literal("")),
    birthDate: z.string().optional().or(z.literal("")),
}).refine(
    (data) =>
        (data.email && data.email !== "") ||
        (data.cin && data.cin !== "") ||
        (data.passportNumber && data.passportNumber !== "") ||
        (data.phone && data.phone !== ""),
    {
        message: "Au moins un moyen d'identification est requis : email, CIN, passeport ou téléphone",
        path: ["email"],
    }
);

export type ClientFormValues = z.infer<typeof clientSchema>;
