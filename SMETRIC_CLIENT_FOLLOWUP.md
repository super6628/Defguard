# S-Metric desktop client follow-up

The Core-side real-time configuration synchronization protocol is implemented independently under the `smetric.config_sync.v1` namespace. The desktop client must be updated before this feature is end-to-end usable.

## Required desktop client work

1. Apply S-Metric Secure branding throughout the desktop client: product name, icons/assets, visible strings, support links, and documentation links where applicable.
2. Add an independent S-Metric config-sync worker.
3. Reuse the existing authenticated `DesktopClient` JWT when connecting to Core.
4. Subscribe to `smetric.config_sync.v1.ConfigSyncService/Subscribe` after client authentication/enrollment.
5. On `ConfigChanged`, fetch the latest effective configuration through the normal authenticated client configuration path. The notification stream intentionally contains no configuration or secrets.
6. Validate the fetched configuration and apply it atomically. Keep the previous working configuration if the new configuration cannot be applied.
7. Call `Acknowledge` with the applied version and success/failure state.
8. Persist the last successfully applied version locally.
9. Call `GetVersion` on startup/reconnect and periodically (target 5-10 minutes) as a reconciliation safety net.
10. Reconnect the streaming RPC using bounded exponential backoff with jitter.

## Protocol behavior

- Core publishes monotonically increasing configuration versions while running.
- Streaming events are lightweight invalidation notifications, not configuration delivery.
- A reconnecting client supplies its last applied version. If Core has a newer version, Core immediately sends a reconciliation event.
- A slow client may skip intermediate events because only the newest effective configuration matters.
- Authentication uses the existing `DesktopClient` claim type.

## Core integration still to complete

Wire `notify_config_changed(reason)` into every Core mutation that can change a desktop client's effective configuration. This should include relevant WireGuard/network/device changes, ACL/policy changes, DNS/routes, user/group access changes, posture policy changes, and other client-visible settings.

The client should not be changed until the Core protocol compiles and the server-side change hooks are validated.
