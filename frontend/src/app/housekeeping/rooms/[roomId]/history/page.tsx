import { RoomCleaningHistoryClient } from "@/components/housekeeping/RoomCleaningHistoryClient";
import { AppLayout } from "@/components/layout/AppLayout";

interface RoomCleaningHistoryPageProps {
    params: Promise<{
        roomId: string;
    }>;
}

export default async function RoomCleaningHistoryPage({
    params,
}: RoomCleaningHistoryPageProps) {
    const { roomId } = await params;

    return (
        <AppLayout>
            <RoomCleaningHistoryClient roomId={Number(roomId)} />
        </AppLayout>
    );
}
