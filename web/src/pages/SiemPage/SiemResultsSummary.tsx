import { useQuery } from '@tanstack/react-query';
import api from '../../shared/api/api';
import { SiemConnectorPanel } from './SiemConnectorPanel';

type Props = {
  visibleCount: number;
  loadedCount: number;
  serverTotal: number;
  hasPageFilters: boolean;
};

export const SiemResultsSummary = ({
  visibleCount,
  loadedCount,
  serverTotal,
  hasPageFilters,
}: Props) => {
  const connectors = useQuery({
    queryKey: ['siem', 'activity-log-streams'],
    queryFn: api.activityLogStream.getStreams,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  return (
    <>
      <div className="siem-results-summary" aria-live="polite">
        <strong>{visibleCount} visible</strong>
        <span>
          {loadedCount} loaded on this page · {serverTotal} matched by server filters
        </span>
        {hasPageFilters && <small>Page-local filters are narrowing the loaded results.</small>}
      </div>

      <SiemConnectorPanel
        streams={connectors.data?.data ?? []}
        isLoading={connectors.isLoading}
        isError={connectors.isError}
        isFetching={connectors.isFetching}
        onRefresh={() => void connectors.refetch()}
      />
    </>
  );
};
