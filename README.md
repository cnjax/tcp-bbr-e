# tcp-bbr-e

`bbr_e` is a Linux TCP congestion-control kernel module: BBRv3 ported to
stock Debian/Ubuntu kernels (no `google/bbr` kernel patches required),
with ZetaTCP-inspired modifications aimed at single-flow throughput over
paths with random, non-congestive packet loss (e.g. lossy wireless/mobile
links, noisy long-haul paths) rather than genuine congestion.

It registers as congestion-control algorithm `bbr_e` (module `tcp_bbr_e`),
deliberately distinct from the in-kernel `bbr`, so both can be loaded and
compared side by side.

## Why

Stock BBR (and Reno/CUBIC) treat any packet loss as a congestion signal
and back off hard. On a path with steady random loss but no real queueing,
that repeatedly collapses a single flow's throughput even though the
bottleneck link is otherwise idle. `bbr_e` adds a lightweight loss
classifier and a few recovery-path changes on top of BBRv3's existing
STARTUP/DRAIN/PROBE_BW/PROBE_RTT state machine to tell "the path dropped a
packet" apart from "the path is congested," and to recover fast when it
guesses right:

- **Loss classification** — each round's RTT is compared against an
  adaptive threshold (soft gate at 1.25×min_rtt, widened by the path's
  own learned loss-free RTT jitter; hard gate at 1.5×min_rtt). Loss
  classified as non-congestive gets a shallow ~5% cut instead of BBR's
  usual 30%. ECN, RTT above the hard gate, or a high loss density still
  fall through to the full congestion response.
- **Quick reprobe** — a bandwidth probe interrupted by non-congestive
  loss retries after ~2 RTTs instead of waiting out BBR's normal
  ~1–1.5s probe interval, with a back-off guard so back-to-back failures
  don't hammer an already-lossy path.
- **Slow-decay bandwidth memory** — the learned max-bandwidth filter
  decays slowly during sustained loss instead of resetting, so recovery
  snaps back toward the previously learned rate instead of re-climbing
  from scratch.
- **Instant re-flight** — on exiting loss recovery, cwnd/pacing jump
  straight back to the model's BDP estimate rather than ramping up over
  several RTTs.
- **Cross-connection path learning** — a small in-kernel, per-destination
  cache (zero extra per-socket bytes) remembers a path's bandwidth,
  min RTT, and RTT jitter across connections. New flows to a
  recently-seen destination warm-start their cwnd/pacing at 75% of the
  learned rate while still running through STARTUP with an unseeded
  bandwidth model, so short flows benefit from what long flows on the
  same path already learned without anchoring on a stale estimate.

See the top-of-file comment in `debian_bbr_v3/tcp_bbr.c` and the inline
comments near `bbr_loss_is_noncongestive()`, `bbr_handle_inflight_too_high()`,
and the `bbr_path_tbl` cache for the exact mechanics.

## Build

```bash
cd debian_bbr_v3
make                 # builds tcp_bbr_e.ko against the running kernel's headers
sudo make load       # insmod
sudo make unload     # rmmod
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr_e
```

Requires the `linux-headers` package matching your running kernel.

## Deploy via DKMS (rebuilds automatically on kernel upgrades)

```bash
./deploy_dkms.sh user@host[:port]
```

Installs the source as a DKMS package (`tcp-bbr-e`, see
`debian_bbr_v3/dkms.conf`) on the target host with `AUTOINSTALL=yes`, so
the module is rebuilt for every new kernel instead of silently going
stale after the next `apt upgrade`. It also sets up boot persistence
(`/etc/modules-load.d`, `/etc/sysctl.d`) and swaps the currently running
module — if the old module is pinned by live sockets, the swap is skipped
without failing and the new build simply takes over on next boot.

## Observability

Runtime stats are exposed via debugfs:

```
/sys/kernel/debug/tcp_bbr_e/
```

including counters for congestive vs. non-congestive loss rounds,
recovery re-flights, quick reprobes, warm starts, and a dump of the
per-destination path cache. Module parameters `learning` and
`warm_start` toggle the cache at runtime for A/B testing.

## Constraints

`struct bbr` is exactly 104 bytes — the stock kernel's
`ICSK_CA_PRIV_SIZE` — enforced by a `BUILD_BUG_ON` at registration.
There is no slack for extra per-socket state, which is why some
upstream BBRv3 bookkeeping (separate probe_rtt_min filter, undo_*
snapshots, ECN-alpha accounting, PLB) isn't present; the 10s min_rtt
window doubles as the PROBE_RTT schedule instead.

Loss detection uses the stock kernel's per-ACK `rate_sample`
(`rs->losses` / `rs->prior_in_flight`); the upstream BBRv3 per-skb
`tx_in_flight` machinery isn't available outside kernels carrying
Google's BBR patches, so it isn't used here.

## Status

This is a single-user-link, throughput-first tuning of BBRv3 — it
intentionally trades away some fairness toward Reno/CUBIC flows sharing
the same bottleneck in exchange for holding throughput on lossy paths.
It is not intended as a general-purpose default congestion control.

## License

GPL-2.0 (see `LICENSE`), consistent with `MODULE_LICENSE("Dual BSD/GPL")`
in the module source. This is a derivative of the Linux kernel's
in-kernel BBRv3 implementation (`net/ipv4/tcp_bbr.c`) by Van Jacobson,
Neal Cardwell, Yuchung Cheng, Soheil Hassas Yeganeh, Priyaranjan Jha,
Yousuk Seung, Kevin Yang, Arjun Roy, and David Morley, ported to build
against stock (non-Google-patched) kernel headers with the
loss-classification and path-learning changes described above layered
on top.
