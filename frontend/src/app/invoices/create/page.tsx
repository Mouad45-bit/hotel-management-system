import { InvoiceCreateClient } from "@/components/invoices/InvoiceCreateClient";
import { AppLayout } from "@/components/layout/AppLayout";

export default function CreateInvoicePage() {
    return (
        <AppLayout>
            <InvoiceCreateClient />
        </AppLayout>
    );
}
