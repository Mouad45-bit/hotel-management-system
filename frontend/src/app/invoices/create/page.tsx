import { InvoiceCreateClient } from "@/components/invoices/InvoiceCreateClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function CreateInvoicePage() {
    return (
        <AppLayout
            title="Générer une facture"
            description="Créer une facture depuis une réservation terminée"
        >
            <InvoiceCreateClient />
        </AppLayout>
    );
}
