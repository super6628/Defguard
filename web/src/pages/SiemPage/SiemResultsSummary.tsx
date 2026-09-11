import { SiemConnectorStatus } from './SiemConnectorStatus';

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
}: Props) => (
  <>
    <div className="siem-results-summary" aria-live="polite">
      <strong>{visibleCount} visible</strong>
      <span>
        {loadedCount} loaded on this page · {serverTotal} matched by server filters
      </span>
      {hasPageFilters && (
        <small>Page-local filters are narrowing the loaded results.</small>
      )}
    </div>
    <SiemConnectorStatus />
  </>
);
