import { InvoiceListClient } from "@/components/invoices/InvoiceListClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function InvoicesPage() {
    return (
        <AppLayout
            title="Factures"
            description="Gestion des factures, paiements et remboursements"
        >
            <InvoiceListClient />
        </AppLayout>
    );
}
