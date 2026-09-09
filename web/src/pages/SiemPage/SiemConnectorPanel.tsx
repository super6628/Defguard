import type { ActivityLogStream } from '../../shared/api/types';

type Props = {
  streams: ActivityLogStream[];
  isLoading: boolean;
  isError: boolean;
  isFetching: boolean;
  onRefresh: () => void;
};

const formatStreamType = (streamType: ActivityLogStream['stream_type']) => {
  switch (streamType) {
    case 'vector_http':
      return 'Vector HTTP';
    case 'logstash_http':
      return 'Logstash HTTP';
    default:
      return streamType.replaceAll('_', ' ');
  }
};

export const SiemConnectorPanel = ({
  streams,
  isLoading,
  isError,
  isFetching,
  onRefresh,
}: Props) => (
  <section className="siem-panel siem-connectors-panel" aria-label="SIEM outbound connectors">
    <div className="siem-panel-header">
      <div>
        <p className="siem-eyebrow">Outbound connectors</p>
        <h3>Activity Log streams</h3>
      </div>
      <div className="siem-panel-actions">
        <span className="siem-panel-meta">
          {isLoading ? 'Loading…' : isError ? 'Status unavailable' : `${streams.length} configured`}
        </span>
        <button
          className="siem-refresh"
          type="button"
          disabled={isFetching}
          onClick={onRefresh}
        >
          {isFetching ? 'Refreshing…' : 'Refresh connectors'}
        </button>
      </div>
    </div>

    {isError ? (
      <div className="siem-state">
        <strong>Connector status could not be loaded</strong>
        <p>
          Security event analysis remains available. Outbound Activity Log stream status can be
          retried independently.
        </p>
      </div>
    ) : !isLoading && streams.length === 0 ? (
      <div className="siem-state">
        <strong>No outbound streams configured</strong>
        <p>
          Activity Log events remain available in SIEM. Configure an Activity Log stream when events
          also need to be forwarded to an external collector.
        </p>
      </div>
    ) : (
      <div className="siem-detections-grid siem-connectors-grid">
        {streams.map((stream) => (
          <article className="siem-detection-card siem-connector-card" key={stream.id}>
            <div className="siem-detection-card-top">
              <span className="siem-live-status">
                <span className="siem-status-dot" />
                Configured
              </span>
              <small>#{stream.id}</small>
            </div>
            <h4>{stream.name}</h4>
            <p>{formatStreamType(stream.stream_type)}</p>
            <dl className="siem-connector-details">
              <div>
                <dt>Destination</dt>
                <dd>{stream.config.url}</dd>
              </div>
              <div>
                <dt>Authentication</dt>
                <dd>{stream.config.username ? 'Credentials configured' : 'No username configured'}</dd>
              </div>
              <div>
                <dt>TLS certificate</dt>
                <dd>{stream.config.cert ? 'Custom certificate configured' : 'Default trust store'}</dd>
              </div>
            </dl>
          </article>
        ))}
      </div>
    )}
  </section>
);
