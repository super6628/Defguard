import type { ActivityLogStream } from '../../shared/api/types';
import './connectors.scss';

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
  }
};

export const formatConnectorDestination = (value: string) => {
  try {
    const destination = new URL(value);
    if (destination.protocol !== 'http:' && destination.protocol !== 'https:') {
      return 'Configured destination';
    }
    return destination.origin;
  } catch {
    return 'Configured destination';
  }
};

export const SiemConnectorPanel = ({
  streams,
  isLoading,
  isError,
  isFetching,
  onRefresh,
}: Props) => (
  <section
    className="siem-panel siem-connectors-panel"
    aria-label="SIEM outbound connectors"
    aria-busy={isLoading || isFetching}
  >
    <div className="siem-panel-header">
      <div>
        <p className="siem-eyebrow">Outbound connectors</p>
        <h3>Activity Log streams</h3>
      </div>
      <div className="siem-panel-actions">
        <span className="siem-panel-meta" aria-live="polite">
          {isLoading ? 'Loading…' : isError ? 'Status unavailable' : `${streams.length} configured`}
        </span>
        <button
          className="siem-refresh"
          type="button"
          disabled={isLoading || isFetching}
          onClick={onRefresh}
        >
          {isFetching ? 'Refreshing…' : 'Refresh connectors'}
        </button>
      </div>
    </div>

    {isLoading ? (
      <div className="siem-state" role="status">
        <strong>Loading connector status</strong>
        <p>Checking the configured Activity Log forwarding destinations.</p>
      </div>
    ) : isError ? (
      <div className="siem-state" role="alert">
        <strong>Connector status could not be loaded</strong>
        <p>
          Security event analysis remains available. Outbound Activity Log stream status can be
          retried independently.
        </p>
      </div>
    ) : streams.length === 0 ? (
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
                <dd title={formatConnectorDestination(stream.config.url)}>
                  {formatConnectorDestination(stream.config.url)}
                </dd>
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
