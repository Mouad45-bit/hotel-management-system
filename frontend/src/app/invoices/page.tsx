import { InvoiceListClient } from "@/components/invoices/InvoiceListClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function InvoicesPage() {
    return (
        <AppLayout
            title="Gestion des factures"
            description="Gestion, suivi et traitement des factures liées aux réservations"
        >
            <InvoiceListClient />
        </AppLayout>
    );
}
