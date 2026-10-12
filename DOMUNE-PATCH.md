# Domune frp client patch

This fork starts from upstream frp v0.71.0, commit
`4a23aa181c1d7e28eecaa8216024ed753b9d27c8` (Apache-2.0).

The client lifecycle fix preserves the existing controller lock while stopping
and reconnecting a service: the worker receives its initial controller directly,
reads subsequent controllers under the lock, and does not publish a newly
connected controller after cancellation. It changes no wire protocol, encryption,
or admission policy.

The fix was previously carried by Domune as
`src/runtime/integrations/frp/patches/control-lifecycle.patch`. This repository now
owns that modification. Domune pins the fork's immutable Go module version and
checksums; its channel integration uses the original upstream import paths.

The default client connector also exposes `NewConnectorWithOptions` with three
narrow integration hooks: a per-connection cloned `TLSConfig`, a complete
`WebsocketURL`, and a raw `DialContext`. The request authority/path/query remain
independent of the raw socket address and TLS peer identity. An explicit TLS
configuration is validated before connection success and, for WSS, before
the WebSocket upgrade; typed hostname and policy errors remain inspectable; nil preserves frp's TLS
configuration and lazy TCP TLS behavior. `NewConnector` keeps its existing
signature and defaults. QUIC uses the cloned TLS configuration; raw DialContext
customization applies to TCP/KCP dialing, including the TCP transport of WS/WSS.
The existing frp/golib proxy negotiation, transport order, binary WebSocket
frames and multiplexing remain in use.

This connector extension requires the companion golib patch described in that
repository's `DOMUNE-PATCH.md`: its `WithDialer` hook and socket cancellation guard
bound the complete proxy/transport handshake without copying proxy protocols.
The dependency is pinned in go.mod to `github.com/w-rui/golib` at
`v0.0.0-20261012153346-e6a4963f844b`. Consumers must repeat that replacement
in their root module because Go does not inherit dependency replacements.

Focused verification uses isolated loopback servers and the race detector:
`go test ./client ./pkg/util/net -race -count=1`.
Coverage includes default WebSocket path/TLS behavior, strict certificate and
hostname rejection before success, a WSS path/query/authority independent from
TLS identity, binary traffic, injected raw dialing through an authenticated HTTP
proxy, and cancellation/release of stalled proxy and TCP/WSS TLS handshakes.
No packaging, deployment or platform matrix is part of this verification.
