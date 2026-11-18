import { InvoicePrintClient } from "@/components/invoices/InvoicePrintClient";

interface InvoicePrintPageProps {
    params: Promise<{
        id: string;
    }>;
}

export default async function InvoicePrintPage({
    params,
}: InvoicePrintPageProps) {
    const { id } = await params;
    const invoiceId = Number(id);

    return <InvoicePrintClient invoiceId={invoiceId} />;
}
