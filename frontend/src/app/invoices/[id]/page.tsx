import { InvoiceDetailClient } from "@/components/invoices/InvoiceDetailClient";
import { AppLayout } from "@/components/layout/AppLayout";

interface InvoiceDetailPageProps {
    params: Promise<{
        id: string;
    }>;
}

export default async function InvoiceDetailPage({
    params,
}: InvoiceDetailPageProps) {
    const { id } = await params;
    const invoiceId = Number(id);

    return (
        <AppLayout
            title="Détail facture"
            description="Consultation financière et actions de cycle de vie"
        >
            <InvoiceDetailClient invoiceId={invoiceId} />
        </AppLayout>
    );
}
