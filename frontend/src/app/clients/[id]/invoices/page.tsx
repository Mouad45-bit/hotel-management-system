import { ClientInvoiceHistoryClient } from "@/components/invoices/ClientInvoiceHistoryClient";
import { AppLayout } from "@/components/layout/AppLayout";

interface ClientInvoiceHistoryPageProps {
    params: Promise<{
        id: string;
    }>;
}

export default async function ClientInvoiceHistoryPage({
    params,
}: ClientInvoiceHistoryPageProps) {
    const { id } = await params;
    const clientId = Number(id);

    return (
        <AppLayout>
            <ClientInvoiceHistoryClient clientId={clientId} />
        </AppLayout>
    );
}
