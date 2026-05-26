# eBPF Sockmap Testing

The eBPF sockmap fast path is optional and should be validated on the target Linux kernel before production use.

Default test runs do not require root or eBPF privileges. Real eBPF tests are ignored and require explicit opt-in.

## Default Tests

```bash
cargo test -p wicket-sockmap
cargo test -p wicket-stream
```

These include non-privileged regression tests that document known sockmap correctness requirements, including proxy tuple mapping and sockhash value sizing.

## Linux eBPF Smoke Tests

Run on a modern Linux host with the privileges required to load and attach eBPF programs, typically root or equivalent `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_PERFMON` depending on kernel policy.

```bash
WICKET_EBPF_TEST=1 cargo test -p wicket-sockmap -- --ignored
```

This validates BPF load/attach and registering a proxy-style socket pair.

## Stream Proxy eBPF Tests

```bash
WICKET_EBPF_TEST=1 cargo test -p wicket-stream --features ebpf ebpf -- --ignored
```

This validates that the stream proxy actually uses the eBPF path, moves bytes in both directions, and keeps a long-lived connection open after the first readable event.

These tests are expected to fail until the known sockmap correctness issues are fixed.
