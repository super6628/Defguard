import { SiemResultsSummary } from './SiemResultsSummary';
import { SiemStatePanel } from './SiemStatePanel';

type Props = {
  isLoading: boolean;
  isError: boolean;
  visibleCount: number;
  loadedCount: number;
  serverTotal: number;
  hasPageFilters: boolean;
  hasActiveFilters: boolean;
  onRetry: () => void;
  onResetFilters: () => void;
};

export const SiemQueueFeedback = ({
  isLoading,
  isError,
  visibleCount,
  loadedCount,
  serverTotal,
  hasPageFilters,
  hasActiveFilters,
  onRetry,
  onResetFilters,
}: Props) => {
  if (isLoading) {
    return <SiemStatePanel title="Loading security events…" />;
  }

  if (isError) {
    return (
      <SiemStatePanel
        title="Activity Log data could not be loaded"
        description="The SIEM queue could not retrieve Activity Log data. Retry the current filters."
        actionLabel="Retry"
        onAction={onRetry}
      />
    );
  }

  if (visibleCount === 0) {
    const noServerMatches = loadedCount === 0;

    return (
      <>
        <SiemResultsSummary
          visibleCount={visibleCount}
          loadedCount={loadedCount}
          serverTotal={serverTotal}
          hasPageFilters={hasPageFilters}
        />
        <SiemStatePanel
          title={noServerMatches ? 'No security events found' : 'No visible events on this page'}
          description={
            noServerMatches
              ? 'No Activity Log events match the current server-side filters.'
              : 'The loaded page contains events, but page-local detection or acknowledgement filters hide them.'
          }
          actionLabel={hasActiveFilters ? 'Reset filters' : undefined}
          onAction={hasActiveFilters ? onResetFilters : undefined}
        />
      </>
    );
  }

  return (
    <SiemResultsSummary
      visibleCount={visibleCount}
      loadedCount={loadedCount}
      serverTotal={serverTotal}
      hasPageFilters={hasPageFilters}
    />
  );
};
