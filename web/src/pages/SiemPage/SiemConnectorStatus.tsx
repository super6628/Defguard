import { useQuery } from '@tanstack/react-query';
import api from '../../shared/api/api';
import { SiemConnectorPanel } from './SiemConnectorPanel';

export const SiemConnectorStatus = () => {
  const connectors = useQuery({
    queryKey: ['siem', 'activity-log-streams'],
    queryFn: api.activityLogStream.getStreams,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  return (
    <SiemConnectorPanel
      streams={connectors.data?.data ?? []}
      isLoading={connectors.isLoading}
      isError={connectors.isError}
      isFetching={connectors.isFetching}
      onRefresh={() => void connectors.refetch()}
    />
  );
};
