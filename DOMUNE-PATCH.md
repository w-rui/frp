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
