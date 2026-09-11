import { describe, expect, it } from 'vitest';
import { formatConnectorDestination } from './SiemConnectorPanel';

describe('formatConnectorDestination', () => {
  it('shows only the origin for a configured connector URL', () => {
    expect(
      formatConnectorDestination(
        'https://collector.example.com/tenant/secret-token/events?api_key=secret#fragment',
      ),
    ).toBe('https://collector.example.com');
  });

  it('removes embedded credentials', () => {
    expect(
      formatConnectorDestination('https://user:password@collector.example.com/events'),
    ).toBe('https://collector.example.com');
  });

  it('does not echo malformed connector values', () => {
    expect(formatConnectorDestination('collector-token-or-secret')).toBe(
      'Configured destination',
    );
  });

  it('does not expose non-HTTP destinations', () => {
    expect(formatConnectorDestination('data:text/plain,collector-secret')).toBe(
      'Configured destination',
    );
    expect(formatConnectorDestination('javascript:collectorSecret()')).toBe(
      'Configured destination',
    );
  });
});
