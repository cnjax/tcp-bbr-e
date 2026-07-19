/* BBR (Bottleneck Bandwidth and RTT) congestion control
 *
 * BBR is a model-based congestion control algorithm that aims for low queues,
 * low loss, and (bounded) Reno/CUBIC coexistence. To maintain a model of the
 * network path, it uses measurements of bandwidth and RTT, as well as (if they
 * occur) packet loss and/or shallow-threshold ECN signals. Note that although
 * it can use ECN or loss signals explicitly, it does not require either; it
 * can bound its in-flight data based on its estimate of the BDP.
 *
 * The model has both higher and lower bounds for the operating range:
 *   lo: bw_lo, inflight_lo: conservative short-term lower bound
 *   hi: bw_hi, inflight_hi: robust long-term upper bound
 * The bandwidth-probing time scale is (a) extended dynamically based on
 * estimated BDP to improve coexistence with Reno/CUBIC; (b) bounded by
 * an interactive wall-clock time-scale to be more scalable and responsive
 * than Reno and CUBIC.
 *
 * Here is a state transition diagram for BBR:
 *
 *             |
 *             V
 *    +---> STARTUP  ----+
 *    |        |         |
 *    |        V         |
 *    |      DRAIN   ----+
 *    |        |         |
 *    |        V         |
 *    +---> PROBE_BW ----+
 *    |      ^    |      |
 *    |      |    |      |
 *    |      +----+      |
 *    |                  |
 *    +---- PROBE_RTT <--+
 *
 * A BBR flow starts in STARTUP, and ramps up its sending rate quickly.
 * When it estimates the pipe is full, it enters DRAIN to drain the queue.
 * In steady state a BBR flow only uses PROBE_BW and PROBE_RTT.
 * A long-lived BBR flow spends the vast majority of its time remaining
 * (repeatedly) in PROBE_BW, fully probing and utilizing the pipe's bandwidth
 * in a fair manner, with a small, bounded queue. *If* a flow has been
 * continuously sending for the entire min_rtt window, and hasn't seen an RTT
 * sample that matches or decreases its min_rtt estimate for 10 seconds, then
 * it briefly enters PROBE_RTT to cut inflight to a minimum value to re-probe
 * the path's two-way propagation delay (min_rtt). When exiting PROBE_RTT, if
 * we estimated that we reached the full bw of the pipe then we enter PROBE_BW;
 * otherwise we enter STARTUP to try to fill the pipe.
 *
 * BBR is described in detail in:
 *   "BBR: Congestion-Based Congestion Control",
 *   Neal Cardwell, Yuchung Cheng, C. Stephen Gunn, Soheil Hassas Yeganeh,
 *   Van Jacobson. ACM Queue, Vol. 14 No. 5, September-October 2016.
 *
 * There is a public e-mail list for discussing BBR development and testing:
 *   https://groups.google.com/forum/#!forum/bbr-dev
 *
 * NOTE: BBR might be used with the fq qdisc ("man tc-fq") with pacing enabled,
 * otherwise TCP stack falls back to an internal pacing using one high
 * resolution timer per TCP socket and may use more resources.
 */
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <net/ipv6.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/win_minmax.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

/* Ported to build against stock Linux 6.12 (Debian 13) headers: the
 * google/bbr-v3 kernel-side extensions (per-skb tx_in_flight accounting,
 * TCP_ECN_LOW accurate-ECN support, CA_EVENT_TLP_RECOVERY, extended
 * tcp_bbr_info) are not available, so those hooks are dropped and the
 * loss-rate checks use the stock per-ACK rate_sample fields instead.
 */

#define BBR_VERSION		3

#define bbr_param(sk,name)	(bbr_ ## name)

/* Cross-connection path learning (ZetaTCP-style learning state-machine):
 * keep a module-global per-destination cache of the learned path model so a
 * new connection to a known destination does not start from scratch.
 */
static bool bbr_learning __read_mostly = true;
module_param_named(learning, bbr_learning, bool, 0644);
MODULE_PARM_DESC(learning, "cross-connection path learning cache");
static bool bbr_warm_start __read_mostly = true;
module_param_named(warm_start, bbr_warm_start, bool, 0644);
MODULE_PARM_DESC(warm_start, "seed new flows from the learned path model");
static uint bbr_warm_start_max_age_sec __read_mostly = 600;
module_param_named(warm_start_max_age_sec, bbr_warm_start_max_age_sec,
		   uint, 0644);
MODULE_PARM_DESC(warm_start_max_age_sec,
		 "max age of a learned bw sample usable for warm start");
static bool bbr_prior_bias __read_mostly = true;
module_param_named(prior_bias, bbr_prior_bias, bool, 0644);
MODULE_PARM_DESC(prior_bias,
		 "let the validated per-path prior modulate loss response");

/* Global counters (debugfs tcp_bbr_e/) so classification and warm-start
 * behavior on live traffic is observable without per-socket state.
 */
static atomic_t bbr_stat_noncong_rounds = ATOMIC_INIT(0);
static atomic_t bbr_stat_cong_rounds = ATOMIC_INIT(0);
static atomic_t bbr_stat_reflights = ATOMIC_INIT(0);
static atomic_t bbr_stat_warm_starts = ATOMIC_INIT(0);
static atomic_t bbr_stat_quick_reprobes = ATOMIC_INIT(0);
static atomic_t bbr_stat_reflight_validated = ATOMIC_INIT(0);
static atomic_t bbr_stat_reflight_refuted = ATOMIC_INIT(0);

/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */
#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)

/* BBR has the following modes for deciding how fast to send: */
enum bbr_mode {
	BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
	BBR_DRAIN,	/* drain any queue created during startup */
	BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
	BBR_PROBE_RTT,	/* cut inflight to min to probe min_rtt */
};

/* How does the incoming ACK stream relate to our bandwidth probing? */
enum bbr_ack_phase {
	BBR_ACKS_INIT,		  /* not probing; not getting probe feedback */
	BBR_ACKS_REFILLING,	  /* sending at est. bw to fill pipe */
	BBR_ACKS_PROBE_STARTING,  /* inflight rising to probe bw */
	BBR_ACKS_PROBE_FEEDBACK,  /* getting feedback from bw probing */
	BBR_ACKS_PROBE_STOPPING,  /* stopped probing; still getting feedback */
};

/* BBR congestion control block.
 * Must fit in ICSK_CA_PRIV_SIZE (104 bytes on stock kernels), so relative to
 * the google/bbr-v3 layout this drops the separate probe_rtt_min filter
 * (min_rtt window doubles as the PROBE_RTT schedule, v1-style), the undo_*
 * snapshot, the ECN alpha bookkeeping, and PLB state.
 */
struct bbr {
	u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
	u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */
	u32	probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
	u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
	u64	cycle_mstamp;	     /* time of this cycle phase start */
	u32     mode:2,		     /* current bbr_mode in state machine */
		prev_ca_state:3,     /* CA state on previous ACK */
		round_start:1,	     /* start of packet-timed tx->ack round? */
		bw_probe_up_rounds:5,   /* cwnd-limited rounds in PROBE_UP */
		try_fast_path:1,	/* can we take fast path? */
		idle_restart:1,	     /* restarting after idle? */
		probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
		init_cwnd:7,         /* initial cwnd */
		loss_was_noncong:1,  /* last loss round judged non-congestive? */
		reflight_pending:1,  /* re-flight awaiting outcome validation? */
		reflight_rounds:2,   /* rounds since the re-flight, saturating */
		path_base_loss:7;    /* cached path ambient loss (BBR_UNIT units,
				      * capped 127) so the per-ACK loss_thresh
				      * check needs no path-table lock */
	u32	pacing_gain:11,	/* current gain for setting pacing rate */
		cwnd_gain:11,	/* current gain for setting cwnd */
		full_bw_reached:1,   /* reached full bw in Startup? */
		full_bw_cnt:3,	/* number of rounds without large bw gains */
		cycle_idx:2,	/* current index in pacing_gain cycle array */
		has_seen_rtt:1, /* have we seen an RTT sample yet? */
		unused_2:3;
	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u32	full_bw;	/* recent bw, to estimate if pipe is full */

	/* For tracking ACK aggregation: */
	u64	ack_epoch_mstamp;	/* start of ACK sampling epoch */
	u16	extra_acked[2];		/* max excess data ACKed in epoch */
	u32	ack_epoch_acked:20,	/* packets (S)ACKed in sampling epoch */
		extra_acked_win_rtts:5,	/* age of extra_acked, in round trips */
		extra_acked_win_idx:1,	/* current index in extra_acked array */
	/* BBR v3 state: */
		full_bw_now:1,		/* recently reached full bw plateau? */
		startup_ecn_rounds:2,	/* consecutive hi ECN STARTUP rounds */
		loss_in_cycle:1,	/* packet loss in this cycle? */
		ecn_in_cycle:1,		/* ECN in this cycle? */
		unused_3:1;
	u32	loss_round_delivered; /* scb->tx.delivered ending loss round */
	u32	bw_latest;	 /* max delivered bw in last round trip */
	u32	bw_lo;		 /* lower bound on sending bandwidth */
	u32	bw_hi[2];	 /* max recent measured bw sample */
	u32	inflight_latest; /* max delivered data in last round trip */
	u32	inflight_lo;	 /* lower bound of inflight data range */
	u32	inflight_hi;	 /* upper bound of inflight data range */
	u32	bw_probe_up_cnt; /* packets delivered per inflight_hi incr */
	u32	bw_probe_up_acks;  /* packets (S)ACKed since inflight_hi incr */
	u32	probe_wait_us;	 /* PROBE_DOWN until next clock-driven probe */
	u32	ecn_eligible:1,	/* sender can use ECN (RTT, handshake)? */
		ecn_alpha:9,	/* EWMA delivered_ce/delivered; 0..256 */
		bw_probe_samples:1,    /* rate samples reflect bw probing? */
		prev_probe_too_high:1, /* did last PROBE_UP go too high? */
		stopped_risky_probe:1, /* last PROBE_UP stopped due to risk? */
		rounds_since_probe:8,  /* packet-timed rounds since probed bw */
		loss_round_start:1,    /* loss_round_delivered round trip? */
		loss_in_round:1,       /* loss marked in this round trip? */
		ecn_in_round:1,	       /* ECN marked in this round trip? */
		ack_phase:3,	       /* bbr_ack_phase: meaning of ACKs */
		loss_events_in_round:4,/* losses in STARTUP round */
		initialized:1;	       /* has bbr_init() been called? */
};

struct bbr_context {
	u32 sample_bw;
};

/* Window length of min_rtt filter (in sec): */
static const u32 bbr_min_rtt_win_sec = 10;
/* Minimum time (in ms) spent at bbr_cwnd_min_target in BBR_PROBE_RTT mode: */
static const u32 bbr_probe_rtt_mode_ms = 200;
/* Proportion of cwnd to estimated BDP in PROBE_RTT, in units of BBR_UNIT: */
static const u32 bbr_probe_rtt_cwnd_gain = BBR_UNIT * 1 / 2;

/* Use min_rtt to help adapt TSO burst size, with smaller min_rtt resulting
 * in bigger TSO bursts. We cut the RTT-based allowance in half
 * for every 2^9 usec (aka 512 us) of RTT, so that the RTT-based allowance
 * is below 1500 bytes after 6 * ~500 usec = 3ms.
 */
static const u32 bbr_tso_rtt_shift = 9;

/* Pace only 1 TSO segment at a time below this rate (1.2Mbps), else 2: */
static const u32 bbr_min_tso_rate = 1200000;

/* Pace at ~1% below estimated bw, on average, to reduce queue at bottleneck.
 * In order to help drive the network toward lower queues and low latency while
 * maintaining high utilization, the average pacing rate aims to be slightly
 * lower than the estimated bandwidth. This is an important aspect of the
 * design.
 */
static const int bbr_pacing_margin_percent = 1;

/* Use an aggressive 4.0x startup pacing gain (vs the default 2.77x doubling
 * ramp) so a single flow injects enough data in the first RTTs to find the
 * path BDP quickly (ZetaTCP-style accelerated startup):
 */
static const int bbr_startup_pacing_gain = BBR_UNIT * 4;
/* The gain for deriving startup cwnd, raised to keep up with the 4x pacing
 * ramp so startup is not cwnd-limited:
 */
static const int bbr_startup_cwnd_gain = BBR_UNIT * 3;
/* The pacing gain in BBR_DRAIN is calculated to typically drain
 * the queue created in BBR_STARTUP in a single round (1/4, matching the
 * 4.0x startup pacing gain):
 */
static const int bbr_drain_gain = BBR_UNIT * 1000 / 4000;
/* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs: */
static const int bbr_cwnd_gain  = BBR_UNIT * 2;
/* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw: */
static const int bbr_pacing_gain[] = {
	BBR_UNIT * 3 / 2,	/* UP: probe aggressively for available bw */
	BBR_UNIT * 91 / 100,	/* DOWN: drain queue and/or yield bw */
	BBR_UNIT,		/* CRUISE: try to use pipe w/ some headroom */
	BBR_UNIT,		/* REFILL: refill pipe to estimated 100% */
};
enum bbr_pacing_gain_phase {
	BBR_BW_PROBE_UP		= 0,  /* push up inflight to probe for bw/vol */
	BBR_BW_PROBE_DOWN	= 1,  /* drain excess inflight from the queue */
	BBR_BW_PROBE_CRUISE	= 2,  /* use pipe, w/ headroom in queue/pipe */
	BBR_BW_PROBE_REFILL	= 3,  /* v2: refill the pipe again to 100% */
};

/* Try to keep at least this many packets in flight, if things go smoothly. For
 * smooth functioning, a sliding window protocol ACKing every other packet
 * needs at least 4 packets in flight:
 */
static const u32 bbr_cwnd_min_target = 4;

/* To estimate if BBR_STARTUP or BBR_BW_PROBE_UP has filled pipe... */
/* If bw has increased significantly (1.25x), there may be more bw available: */
static const u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4;
/* Estimate pipe is full only after 5 rounds w/o significant bw growth,
 * tolerating short-term queueing to keep probing for the true top speed
 * before entering DRAIN:
 */
static const u32 bbr_full_bw_cnt = 5;

/* Gain factor for adding extra_acked to target cwnd: */
static const int bbr_extra_acked_gain = BBR_UNIT;
/* Window length of extra_acked window. */
static const u32 bbr_extra_acked_win_rtts = 5;
/* Max allowed val for ack_epoch_acked, after which sampling epoch is reset */
static const u32 bbr_ack_epoch_acked_reset_thresh = 1U << 20;
/* Time period for clamping cwnd increment due to ack aggregation */
static const u32 bbr_extra_acked_max_us = 100 * 1000;

/* On losses, scale down inflight and pacing rate by beta scaled by BBR_SCALE.
 * No loss response when 0.
 */
static const u32 bbr_beta = BBR_UNIT * 30 / 100;

/* Backoff for loss classified as non-congestive (RTT near min_rtt, no ECN,
 * loss rate under loss_thresh): a near-zero cut, so random/wireless-style
 * loss does not pollute bw_lo/inflight_lo.
 */
static const u32 bbr_noncong_beta = BBR_UNIT * 5 / 100;

/* Loss is judged non-congestive only while RTT stays below this multiple of
 * min_rtt (i.e. no standing queue is building). This soft gate is widened by
 * the path's learned loss-free jitter (see bbr_loss_is_noncongestive()):
 */
static const u32 bbr_noncong_rtt_thresh = BBR_UNIT * 5 / 4;

/* Hard ceiling: RTT above this multiple of min_rtt always means congestion,
 * regardless of jitter allowance. This caps how far the learned-jitter
 * widening can stretch the soft gate. (A delivery-rate "gray zone" between
 * the gates was tried and removed: when the flow's max-bw memory
 * underestimates the true bottleneck rate, delivery always looks "high" and
 * genuine queue-building loss gets misread as non-congestive.)
 */
static const u32 bbr_noncong_rtt_hard = BBR_UNIT * 3 / 2;

/* Quick reprobe: when a bandwidth probe is stopped by loss classified as
 * non-congestive, wait only this many min_rtt round trips before probing
 * again, instead of the ~1-1.5s clock-driven wait. Random loss should not
 * idle the search for the path ceiling; genuine congestion still classifies
 * congestive and keeps the full wait.
 */
static const u32 bbr_noncong_reprobe_rtts = 2;

/* Upper cap on the sample loss rate that can still be classified as
 * non-congestive. Deliberately above loss_thresh: on this deployment's path
 * random loss runs 10-20%, and loss rate alone does not distinguish
 * congestion — the RTT and ECN gates above are the real discriminators.
 */
static const u32 bbr_noncong_loss_cap = BBR_UNIT * 25 / 100;

/* The initial value for ecn_alpha; 1.0 allows a flow to respond quickly
 * to congestion if the bottleneck is congested when the flow starts up.
 */
static const u32 bbr_ecn_alpha_init = BBR_UNIT;

/* On ECN, cut inflight_lo to (1 - ecn_factor * ecn_alpha) scaled by BBR_SCALE.
 * No ECN based bounding when 0.
 */
static const u32 bbr_ecn_factor = BBR_UNIT * 1 / 3;	 /* 1/3 = 33% */

/* Estimate bw probing has gone too far if CE ratio exceeds this threshold.
 * Scaled by BBR_SCALE. Disabled when 0.
 */
static const u32 bbr_ecn_thresh = BBR_UNIT * 1 / 2;  /* 1/2 = 50% */

/* If non-zero, if in a cycle with no losses but some ECN marks, after ECN
 * clears then make the first round's increment to inflight_hi the following
 * fraction of inflight_hi.
 */
static const u32 bbr_ecn_reprobe_gain = BBR_UNIT * 1 / 2;

/* Estimate bw probing has gone too far if loss rate exceeds this level.
 * Raised to 10% for this deployment: ambient random loss on the real path
 * runs 10-20%, and at 3% every PROBE_UP was judged "too high" immediately,
 * crippling bandwidth probing. Congestion protection still comes from the
 * RTT-inflation gate in bbr_loss_is_noncongestive().
 */
static const u32 bbr_loss_thresh = BBR_UNIT * 10 / 100;  /* 10% loss */

/* Exit STARTUP if number of loss marking events in a Recovery round is >= N,
 * and loss rate is higher than bbr_loss_thresh.
 * Disabled if 0. Set to 15 (the saturation value of the 4-bit
 * loss_events_in_round counter) so 10-20% ambient random loss cannot end
 * STARTUP early; only a fully saturated loss round plus >loss_thresh rate
 * does.
 */
static const u32 bbr_full_loss_cnt = 15;

/* Fraction of unutilized headroom to try to leave in path upon high loss.
 * Reduced to 5% so CRUISE keeps pressure on idle bandwidth.
 */
static const u32 bbr_inflight_headroom = BBR_UNIT * 5 / 100;

/* How much do we increase cwnd_gain when probing for bandwidth in
 * BBR_BW_PROBE_UP? This specifies the increment in units of
 * BBR_UNIT/4. Raised to 2 (meaning 0.5) for more aggressive probing.
 * The min value is 0 (meaning 0.0); max is 3 (meaning 0.75).
 */
static const u32 bbr_bw_probe_cwnd_gain = 2;

/* Max number of packet-timed rounds to wait before probing for bandwidth.  If
 * we want to tolerate 1% random loss per round, and not have this cut our
 * inflight too much, we must probe for bw periodically on roughly this scale.
 * If low, limits Reno/CUBIC coexistence; if high, limits loss tolerance.
 * We aim to be fair with Reno/CUBIC up to a BDP of at least:
 *  BDP = 25Mbps * .030sec /(1514bytes) = 61.9 packets
 */
static const u32 bbr_bw_probe_max_rounds = 63;

/* Max amount of randomness to inject in round counting for Reno-coexistence.
 */
static const u32 bbr_bw_probe_rand_rounds = 2;

/* Use BBR-native probe time scale starting at this many usec.
 * We aim to be fair with Reno/CUBIC up to an inter-loss time epoch of at least:
 *  BDP*RTT = 25Mbps * .030sec /(1514bytes) * 0.030sec = 1.9 secs
 */
static const u32 bbr_bw_probe_base_us = 1 * USEC_PER_SEC;  /* 1 sec: probe
	twice as often as stock BBRv3 to reclaim idle bandwidth quickly */

/* Use BBR-native probes spread over this many usec: */
static const u32 bbr_bw_probe_rand_us = USEC_PER_SEC / 2;  /* 0.5 secs */

/* Use fast path if app-limited, no loss/ECN, and target cwnd was reached? */
static const bool bbr_fast_path = true;

static u32 bbr_max_bw(const struct sock *sk);
static u32 bbr_bw(const struct sock *sk);
static u32 bbr_bdp(struct sock *sk, u32 bw, int gain);
static void bbr_exit_probe_rtt(struct sock *sk);
static void bbr_reset_congestion_signals(struct sock *sk);

static void bbr_check_probe_rtt_done(struct sock *sk);

/* Do we estimate that STARTUP filled the pipe? */
static bool bbr_full_bw_reached(const struct sock *sk)
{
	const struct bbr *bbr = inet_csk_ca(sk);

	return bbr->full_bw_reached;
}

/* Return the windowed max recent bandwidth sample, in pkts/uS << BW_SCALE. */
static u32 bbr_max_bw(const struct sock *sk)
{
	const struct bbr *bbr = inet_csk_ca(sk);

	return max(bbr->bw_hi[0], bbr->bw_hi[1]);
}

/* Return the estimated bandwidth of the path, in pkts/uS << BW_SCALE. */
static u32 bbr_bw(const struct sock *sk)
{
	const struct bbr *bbr = inet_csk_ca(sk);

	return min(bbr_max_bw(sk), bbr->bw_lo);
}

/* Return maximum extra acked in past k-2k round trips,
 * where k = bbr_extra_acked_win_rtts.
 */
static u16 bbr_extra_acked(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return max(bbr->extra_acked[0], bbr->extra_acked[1]);
}

/* ---- Cross-connection path learning cache ----
 *
 * The ZetaTCP-style learning state-machine that outlives a single connection.
 * Keyed by destination address; lives in module-global memory, so it costs
 * zero bytes of the 104-byte per-socket area. Per-socket code touches it only
 * at low-frequency points: init (warm start), end of each round trip
 * (jitter/classification bookkeeping), once per PROBE_BW cycle and at socket
 * release (bw/min_rtt write-back).
 */

#define BBR_PATH_HASH_BITS	8	/* 256 buckets */
#define BBR_PATH_BUCKET_MAX	8	/* per-bucket cap: ~2K entries, ~128KB */

struct bbr_path_entry {
	struct hlist_node node;
	struct in6_addr	daddr;		/* v4 stored as v4-mapped */
	u32	bw;		/* learned max bw, pkts/uS << BW_SCALE */
	u32	bw_avg;		/* running mean of per-round delivered bw:
				 * what flows here actually sustain, ambient
				 * loss and competing traffic included */
	u32	min_rtt_us;	/* learned path min RTT */
	u32	jitter_us;	/* EWMA RTT deviation in loss-free rounds */
	u32	noncong;	/* EWMA share of loss rounds judged noncong,
				 * in units of BBR_UNIT */
	u32	reflight_ok;	/* re-flights whose delivery held up after */
	u32	reflight_bad;	/* re-flights refuted by collapse/RTO after */
	u32	base_loss;	/* learned ambient loss rate, BBR_UNIT units;
				 * 0 = unknown (fall back to global caps) */
	u32	flows;		/* completed flows that contributed */
	u32	bw_stamp;	/* jiffies32 of last bw/min_rtt write-back */
	u32	stamp;		/* jiffies32 of last touch (for eviction) */
};

static DEFINE_SPINLOCK(bbr_path_lock);
static DEFINE_HASHTABLE(bbr_path_tbl, BBR_PATH_HASH_BITS);
static u32 bbr_path_entry_cnt;		/* exposed read-only via debugfs */
static u32 bbr_path_hash_seed __read_mostly;

static void bbr_path_key(const struct sock *sk, struct in6_addr *key)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6) {
		/* v4-mapped v6 daddr already matches the v4 encoding below */
		*key = sk->sk_v6_daddr;
		return;
	}
#endif
	ipv6_addr_set_v4mapped(sk->sk_daddr, key);
}

static u32 bbr_path_hash(const struct in6_addr *key)
{
	return jhash2((const u32 *)key, 4, bbr_path_hash_seed);
}

/* Find (optionally create) the entry for key. Caller holds bbr_path_lock.
 * When a bucket is full, the stalest entry in it is recycled.
 */
static struct bbr_path_entry *__bbr_path_lookup(const struct in6_addr *key,
						u32 hash, bool create)
{
	struct bbr_path_entry *e, *stale = NULL;
	int depth = 0;

	hash_for_each_possible(bbr_path_tbl, e, node, hash) {
		if (ipv6_addr_equal(&e->daddr, key))
			return e;
		depth++;
		if (!stale || before(e->stamp, stale->stamp))
			stale = e;
	}
	if (!create)
		return NULL;
	if (depth >= BBR_PATH_BUCKET_MAX) {
		e = stale;	/* recycle the stalest entry in this bucket */
		e->daddr = *key;
		e->bw = 0;
		e->bw_avg = 0;
		e->min_rtt_us = 0;
		e->jitter_us = 0;
		e->noncong = 0;
		e->reflight_ok = 0;
		e->reflight_bad = 0;
		e->base_loss = 0;
		e->flows = 0;
		e->bw_stamp = 0;
		e->stamp = tcp_jiffies32;
		return e;
	}
	e = kzalloc(sizeof(*e), GFP_ATOMIC);
	if (!e)
		return NULL;
	e->daddr = *key;
	e->stamp = tcp_jiffies32;
	hash_add(bbr_path_tbl, &e->node, hash);
	bbr_path_entry_cnt++;
	return e;
}

/* Snapshot the path entry for this socket's destination, if one exists. */
static bool bbr_path_peek(const struct sock *sk, struct bbr_path_entry *snap)
{
	struct bbr_path_entry *e;
	struct in6_addr key;
	bool found = false;

	bbr_path_key(sk, &key);
	spin_lock_bh(&bbr_path_lock);
	e = __bbr_path_lookup(&key, bbr_path_hash(&key), false);
	if (e) {
		*snap = *e;
		found = true;
	}
	spin_unlock_bh(&bbr_path_lock);
	return found;
}

/* A round trip completed with no loss/ECN: learn the path's baseline RTT
 * jitter, which the loss classifier uses to widen its soft RTT gate. Learned
 * only from clean rounds so congestion episodes cannot inflate it.
 */
static void bbr_path_note_clean_round(const struct sock *sk, u32 jitter_us)
{
	struct bbr_path_entry *e;
	struct in6_addr key;
	s32 delta;

	bbr_path_key(sk, &key);
	spin_lock_bh(&bbr_path_lock);
	e = __bbr_path_lookup(&key, bbr_path_hash(&key), true);
	if (e) {
		delta = (s32)(jitter_us - e->jitter_us);
		e->jitter_us += delta >> 2;
		e->stamp = tcp_jiffies32;
	}
	spin_unlock_bh(&bbr_path_lock);
}

/* Fold one round's delivered bandwidth into the path's running mean. The
 * full-bw plateau latch answers "has growth stopped?" and is defeated by
 * recovery-batching spikes on fast-varying links; what warm start actually
 * needs is "what do flows here sustain?". A dual-rate EWMA gives both fast
 * acquisition and stable tracking: quarter-steps while the sample is more
 * than 2x away from the mean (locks on within ~5-8 rounds after the ramp),
 * sixteenth-steps inside the band (smooths steady-state oscillation).
 */
static void bbr_path_note_round_bw(const struct sock *sk, u32 bw)
{
	struct bbr_path_entry *e;
	struct in6_addr key;

	bbr_path_key(sk, &key);
	spin_lock_bh(&bbr_path_lock);
	e = __bbr_path_lookup(&key, bbr_path_hash(&key), true);
	if (e) {
		if (!e->bw_avg)
			e->bw_avg = bw;
		else if (bw > (e->bw_avg << 1) || bw < (e->bw_avg >> 1))
			e->bw_avg += ((s32)(bw - e->bw_avg)) >> 2;
		else
			e->bw_avg += ((s32)(bw - e->bw_avg)) >> 4;
		e->stamp = tcp_jiffies32;
	}
	spin_unlock_bh(&bbr_path_lock);
}

/* Record how a loss round was classified, as a slow EWMA. Not yet used to
 * bias classification; exposed via debugfs to characterize each path.
 */
static void bbr_path_note_loss_round(const struct sock *sk, bool noncong)
{
	struct bbr_path_entry *e;
	struct in6_addr key;
	u32 target = noncong ? BBR_UNIT : 0;

	bbr_path_key(sk, &key);
	spin_lock_bh(&bbr_path_lock);
	e = __bbr_path_lookup(&key, bbr_path_hash(&key), true);
	if (e) {
		e->noncong += ((s32)(target - e->noncong)) >> 3;
		e->stamp = tcp_jiffies32;
	}
	spin_unlock_bh(&bbr_path_lock);
}

/* Record whether a non-congestive verdict survived contact with reality:
 * after a recovery-exit re-flight, did delivery hold near the learned bw
 * (validated), or did the flow collapse into another loss episode / RTO
 * (refuted)? Unlike the noncong EWMA above -- which records the classifier's
 * own output and so cannot be fed back without a self-reinforcing loop --
 * these outcome counters are the ground truth a later phase can safely use
 * as a per-path prior. Phase 1: record only, no behavior change.
 */
static void bbr_note_reflight_outcome(struct sock *sk, bool ok)
{
	struct bbr_path_entry *e;
	struct in6_addr key;

	if (ok)
		atomic_inc(&bbr_stat_reflight_validated);
	else
		atomic_inc(&bbr_stat_reflight_refuted);
	if (!bbr_learning)
		return;
	bbr_path_key(sk, &key);
	spin_lock_bh(&bbr_path_lock);
	e = __bbr_path_lookup(&key, bbr_path_hash(&key), true);
	if (e) {
		if (ok)
			e->reflight_ok = min_t(u32, e->reflight_ok + 1, 0xFFFF);
		else
			e->reflight_bad = min_t(u32, e->reflight_bad + 1, 0xFFFF);
		e->stamp = tcp_jiffies32;
	}
	spin_unlock_bh(&bbr_path_lock);
}

/* The path's validated non-congestive prior, in BBR_UNIT units. Derived only
 * from the outcome counters above (never from the classifier's own output, to
 * avoid a self-reinforcing loop). A refuted re-flight weighs double: judging
 * congestion "random" costs an RTO episode, judging random loss "congestion"
 * only costs an over-cut. BBR_UNIT/2 is the neutral point at which every
 * modulation below reduces exactly to the pre-prior behavior; returned when
 * evidence is thin (<8 scored re-flights) or prior_bias is off.
 */
static u32 bbr_prior_from_entry(const struct bbr_path_entry *pe)
{
	u32 n = pe->reflight_ok + pe->reflight_bad;

	if (!bbr_prior_bias || n < 8)
		return BBR_UNIT / 2;
	return div_u64((u64)pe->reflight_ok * BBR_UNIT,
		       pe->reflight_ok + 2 * pe->reflight_bad);
}

/* Probe-stop loss threshold relative to the path's learned ambient loss
 * rate. The global 10% constant was tuned for this deployment's 10-20%
 * ambient-loss paths; the learned baseline gives a clean path back its
 * stock-like probing prudence (fewer self-induced losses at real
 * bottlenecks) instead of inheriting that tolerance. The learned value can
 * only TIGHTEN below the global, never loosen past it, so self-induced loss
 * polluting the baseline is bounded at exactly the pre-round-9 behavior.
 * base_loss == 0 means unknown: use the global.
 *
 * Deliberately NOT applied to noncong_loss_cap: the classifier's density
 * cap stays absolute at 25%, because a historically-clean path that
 * suddenly shows RTT-flat 20% loss (wifi behind a wall -- the flagship
 * scenario) must still classify non-congestive; RTT inflation, not loss
 * rate vs history, is the congestion signal.
 */
static u32 bbr_loss_thresh_eff(u32 base_loss)
{
	if (!base_loss)
		return bbr_loss_thresh;
	return clamp_t(u32, base_loss + BBR_UNIT * 3 / 100,
		       BBR_UNIT * 3 / 100, bbr_loss_thresh);
}

static u32 bbr_noncong_prior(struct sock *sk)
{
	struct bbr_path_entry pe;

	if (!bbr_prior_bias || !bbr_learning || !bbr_path_peek(sk, &pe))
		return BBR_UNIT / 2;
	return bbr_prior_from_entry(&pe);
}

/* Effective backoff for a round judged non-congestive: the near-zero cut
 * while the path's verdicts keep being validated, interpolated toward the
 * full congestive beta as refuted re-flights drag the prior below neutral.
 * A path where "non-congestive" verdicts keep ending in collapse/RTO pays
 * progressively closer to the real price.
 */
static u32 bbr_noncong_beta_eff(struct sock *sk)
{
	u32 lo = bbr_param(sk, noncong_beta);
	u32 hi = bbr_param(sk, beta);
	u32 prior = bbr_noncong_prior(sk);

	if (prior >= BBR_UNIT / 2)
		return lo;
	return lo + (u32)div_u64((u64)(hi - lo) * (BBR_UNIT / 2 - prior),
				 BBR_UNIT / 2);
}

/* Write the flow's converged model back into the path cache. Called once per
 * PROBE_BW cycle for long flows and at socket release. The old bw decays
 * 12.5% per write-back unless re-confirmed, so a stale/unvalidated seed
 * fades across generations instead of self-perpetuating.
 */
static void bbr_path_flow_update(struct sock *sk, bool flow_done)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	struct bbr_path_entry *e;
	struct in6_addr key;
	u32 bw;

	if (!bbr->initialized)
		return;
	/* Remember the sustained level, not the peak: the max-bw filter keeps
	 * any single inflated sample (loss-recovery ACK batching spiked one
	 * path's memory to 5x its real capacity), while full_bw is the plateau
	 * estimate that a lone spike only pollutes transiently. Taking the min
	 * means a spike must fool both filters at once to enter the cache.
	 * full_bw can be 0 right after a reset (probe start, RTO); the max-bw
	 * fallback there is safe because mid-flow writes only ratchet up and
	 * the release path applies its generation decay regardless.
	 */
	bw = bbr_max_bw(sk);
	if (bbr->full_bw)
		bw = min(bw, bbr->full_bw);
	if (!bw || !bbr->min_rtt_us || bbr->min_rtt_us == ~0U)
		return;
	/* Only flows with a real converged model may teach the cache -- short
	 * unconverged flows write nothing (round-5 lesson). But on spiky
	 * high-loss paths the full-bw plateau detector can be re-armed by
	 * recovery ACK-batching spikes for tens of seconds, and if no flow
	 * ever writes, bw_stamp goes stale and warm start dies until a lucky
	 * flow converges (observed as a morning-long lockout). A flow that
	 * has delivered thousands of packets at steady state is not "short
	 * and unconverged" no matter what the plateau detector says, so it
	 * qualifies too; the min(max_bw, full_bw) write value keeps its
	 * contribution spike-resistant either way.
	 */
	if (tp->delivered < 30 ||
	    (!bbr_full_bw_reached(sk) &&
	     tp->delivered < max(4096U, 4 * bbr_bdp(sk, bw, BBR_UNIT))))
		return;

	bbr_path_key(sk, &key);
	spin_lock_bh(&bbr_path_lock);
	e = __bbr_path_lookup(&key, bbr_path_hash(&key), true);
	if (e) {
		/* Mid-flow updates only raise the memory; the 12.5% decay
		 * generation applies once per completed flow. Otherwise
		 * per-cycle updates during a loss episode ratchet the
		 * learned bw down 12.5% per second-ish, poisoning the cache
		 * with exactly the transient the cache exists to survive.
		 */
		if (flow_done)
			e->bw = max(bw, e->bw - (e->bw >> 3));
		else
			e->bw = max(bw, e->bw);
		if (!e->min_rtt_us || bbr->min_rtt_us < e->min_rtt_us)
			e->min_rtt_us = bbr->min_rtt_us;
		else	/* track upward RTT drift slowly (route changes) */
			e->min_rtt_us +=
				(bbr->min_rtt_us - e->min_rtt_us) >> 2;
		if (flow_done) {
			u32 ratio;

			e->flows = min_t(u32, e->flows + 1, 0xFFFF);
			/* Age the outcome evidence one generation per
			 * completed converged flow, so a path that changed
			 * (bottleneck gone, route moved) can outgrow its old
			 * prior instead of being penalized forever.
			 */
			e->reflight_ok -= e->reflight_ok >> 3;
			e->reflight_bad -= e->reflight_bad >> 3;
			/* Learn the ambient loss rate from the flow's
			 * lifetime loss ratio. Seed directly on first write:
			 * an EWMA climbing from zero would leave the derived
			 * caps far too tight for a genuinely lossy path's
			 * next few flows.
			 */
			ratio = max_t(u32, 1,
				      div_u64((u64)tp->lost * BBR_UNIT,
					      tp->delivered + tp->lost));
			if (!e->base_loss)
				e->base_loss = ratio;
			else
				e->base_loss +=
					((s32)(ratio - e->base_loss)) >> 2;
		}
		e->bw_stamp = tcp_jiffies32;
		e->stamp = tcp_jiffies32;
	}
	spin_unlock_bh(&bbr_path_lock);
}

static void bbr_path_flush(void)
{
	struct bbr_path_entry *e;
	struct hlist_node *tmp;
	int bkt;

	spin_lock_bh(&bbr_path_lock);
	hash_for_each_safe(bbr_path_tbl, bkt, tmp, e, node) {
		hash_del(&e->node);
		kfree(e);
	}
	bbr_path_entry_cnt = 0;
	spin_unlock_bh(&bbr_path_lock);
}

static int bbr_path_show(struct seq_file *m, void *v)
{
	struct bbr_path_entry *e;
	u32 now = tcp_jiffies32;
	int bkt;

	seq_puts(m, "daddr bw_mbps bw_avg_mbps min_rtt_us jitter_us noncong_x256 base_loss_x256 reflight_ok reflight_bad flows bw_age_s touch_age_s\n");
	spin_lock_bh(&bbr_path_lock);
	hash_for_each(bbr_path_tbl, bkt, e, node) {
		seq_printf(m, "%pI6c %llu %llu %u %u %u %u %u %u %u %u %u\n",
			   &e->daddr,
			   ((u64)e->bw * 12000) >> BW_SCALE, /* ~1500B MSS */
			   ((u64)e->bw_avg * 12000) >> BW_SCALE,
			   e->min_rtt_us, e->jitter_us, e->noncong,
			   e->base_loss,
			   e->reflight_ok, e->reflight_bad, e->flows,
			   e->bw_stamp ? (now - e->bw_stamp) / HZ : 0,
			   (now - e->stamp) / HZ);
	}
	spin_unlock_bh(&bbr_path_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(bbr_path);

/* ---- end path learning cache ---- */

/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
static u64 bbr_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain,
				  int margin)
{
	unsigned int mss = tcp_sk(sk)->mss_cache;

	rate *= mss;
	rate *= gain;
	rate >>= BBR_SCALE;
	rate *= USEC_PER_SEC / 100 * (100 - margin);
	rate >>= BW_SCALE;
	rate = max(rate, 1ULL);
	return rate;
}

static u64 bbr_bw_bytes_per_sec(struct sock *sk, u64 rate)
{
	return bbr_rate_bytes_per_sec(sk, rate, BBR_UNIT, 0);
}

/* Convert a BBR bw and gain factor to a pacing rate in bytes per second. */
static unsigned long bbr_bw_to_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	u64 rate = bw;

	rate = bbr_rate_bytes_per_sec(sk, rate, gain,
				      bbr_pacing_margin_percent);
	rate = min_t(u64, rate, READ_ONCE(sk->sk_max_pacing_rate));
	return rate;
}

/* Initialize pacing rate to: startup_pacing_gain * init_cwnd / RTT. */
static void bbr_init_pacing_rate_from_rtt(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;
	u32 rtt_us;

	if (tp->srtt_us) {		/* any RTT sample yet? */
		rtt_us = max(tp->srtt_us >> 3, 1U);
		bbr->has_seen_rtt = 1;
	} else {			 /* no RTT sample yet */
		rtt_us = USEC_PER_MSEC;	 /* use nominal default RTT */
	}
	bw = (u64)tcp_snd_cwnd(tp) * BW_UNIT;
	do_div(bw, rtt_us);
	WRITE_ONCE(sk->sk_pacing_rate,
		   bbr_bw_to_pacing_rate(sk, bw, bbr_param(sk, startup_pacing_gain)));
}

/* Pace using current bw estimate and a gain factor. */
static void bbr_set_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	unsigned long rate = bbr_bw_to_pacing_rate(sk, bw, gain);

	if (unlikely(!bbr->has_seen_rtt && tp->srtt_us))
		bbr_init_pacing_rate_from_rtt(sk);
	if (bbr_full_bw_reached(sk) || rate > READ_ONCE(sk->sk_pacing_rate))
		WRITE_ONCE(sk->sk_pacing_rate, rate);
}

/* Return the number of segments BBR would like in a TSO/GSO skb, given a
 * particular max gso size as a constraint. TODO: make this simpler and more
 * consistent by switching bbr to just call tcp_tso_autosize().
 */
static u32 bbr_tso_segs_generic(struct sock *sk, unsigned int mss_now,
				u32 gso_max_size)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 segs, r;
	u64 bytes;

	/* Budget a TSO/GSO burst size allowance based on bw (pacing_rate). */
	bytes = READ_ONCE(sk->sk_pacing_rate) >> READ_ONCE(sk->sk_pacing_shift);

	/* Budget a TSO/GSO burst size allowance based on min_rtt. For every
	 * K = 2^tso_rtt_shift microseconds of min_rtt, halve the burst.
	 * The min_rtt-based burst allowance is: 64 KBytes / 2^(min_rtt/K)
	 */
	if (bbr_param(sk, tso_rtt_shift)) {
		r = bbr->min_rtt_us >> bbr_param(sk, tso_rtt_shift);
		if (r < BITS_PER_TYPE(u32))   /* prevent undefined behavior */
			bytes += GSO_LEGACY_MAX_SIZE >> r;
	}

	bytes = min_t(u32, bytes, gso_max_size - 1 - MAX_TCP_HEADER);
	segs = max_t(u32, bytes / mss_now,
		     sock_net(sk)->ipv4.sysctl_tcp_min_tso_segs);
	return segs;
}

/* Stock kernels only expose the min_tso_segs hook (not the v3 tso_segs
 * hook), so cap only the lower bound here; tcp_tso_autosize() does the rest.
 */
__bpf_kfunc static u32 bbr_min_tso_segs(struct sock *sk)
{
	return READ_ONCE(sk->sk_pacing_rate) < (bbr_min_tso_rate >> 3) ? 1 : 2;
}

/* TSO burst goal using mss_cache, ignoring driver's sk_gso_max_size. */
static u32 bbr_tso_segs_goal(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	return bbr_tso_segs_generic(sk, tp->mss_cache, GSO_LEGACY_MAX_SIZE);
}

/* Save "last known good" cwnd so we can restore it after losses or PROBE_RTT */
static void bbr_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	if (bbr->prev_ca_state < TCP_CA_Recovery && bbr->mode != BBR_PROBE_RTT)
		bbr->prior_cwnd = tcp_snd_cwnd(tp);  /* this cwnd is good enough */
	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
		bbr->prior_cwnd = max(bbr->prior_cwnd, tcp_snd_cwnd(tp));
}

__bpf_kfunc static void bbr_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	if (event == CA_EVENT_TX_START) {
		if (!tp->app_limited)
			return;
		bbr->idle_restart = 1;
		bbr->ack_epoch_mstamp = tp->tcp_mstamp;
		bbr->ack_epoch_acked = 0;
		/* Avoid pointless buffer overflows: pace at est. bw if we don't
		 * need more speed (we're restarting from idle and app-limited).
		 */
		if (bbr->mode == BBR_PROBE_BW)
			bbr_set_pacing_rate(sk, bbr_bw(sk), BBR_UNIT);
		else if (bbr->mode == BBR_PROBE_RTT)
			bbr_check_probe_rtt_done(sk);
	}
}

/* Calculate bdp based on min RTT and the estimated bottleneck bandwidth:
 *
 * bdp = ceil(bw * min_rtt * gain)
 *
 * The key factor, gain, controls the amount of queue. While a small gain
 * builds a smaller queue, it becomes more vulnerable to noise in RTT
 * measurements (e.g., delayed ACKs or other ACK compression effects). This
 * noise may cause BBR to under-estimate the rate.
 */
static u32 bbr_bdp(struct sock *sk, u32 bw, int gain)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bdp;
	u64 w;

	/* If we've never had a valid RTT sample, cap cwnd at the initial
	 * default. This should only happen when the connection is not using TCP
	 * timestamps and has retransmitted all of the SYN/SYNACK/data packets
	 * ACKed so far. In this case, an RTO can cut cwnd to 1, in which
	 * case we need to slow-start up toward something safe: initial cwnd.
	 */
	if (unlikely(bbr->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
		return bbr->init_cwnd;  /* be safe: cap at initial cwnd */

	w = (u64)bw * bbr->min_rtt_us;

	/* Apply a gain to the given value, remove the BW_SCALE shift, and
	 * round the value up to avoid a negative feedback loop.
	 */
	bdp = (((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT;

	return bdp;
}

/* To achieve full performance in high-speed paths, we budget enough cwnd to
 * fit full-sized skbs in-flight on both end hosts to fully utilize the path:
 *   - one skb in sending host Qdisc,
 *   - one skb in sending host TSO/GSO engine
 *   - one skb being received by receiver host LRO/GRO/delayed-ACK engine
 * Don't worry, at low rates this won't bloat cwnd because
 * in such cases tso_segs_goal is small. The minimum cwnd is 4 packets,
 * which allows 2 outstanding 2-packet sequences, to try to keep pipe
 * full even with ACK-every-other-packet delayed ACKs.
 */
static u32 bbr_quantization_budget(struct sock *sk, u32 cwnd)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 tso_segs_goal;

	tso_segs_goal = 3 * bbr_tso_segs_goal(sk);

	/* Allow enough full-sized skbs in flight to utilize end systems. */
	cwnd = max_t(u32, cwnd, tso_segs_goal);
	cwnd = max_t(u32, cwnd, bbr_param(sk, cwnd_min_target));
	/* Ensure gain cycling gets inflight above BDP even for small BDPs. */
	if (bbr->mode == BBR_PROBE_BW && bbr->cycle_idx == BBR_BW_PROBE_UP)
		cwnd += 2;

	return cwnd;
}

/* Find inflight based on min RTT and the estimated bottleneck bandwidth. */
static u32 bbr_inflight(struct sock *sk, u32 bw, int gain)
{
	u32 inflight;

	inflight = bbr_bdp(sk, bw, gain);
	inflight = bbr_quantization_budget(sk, inflight);

	return inflight;
}

/* With pacing at lower layers, there's often less data "in the network" than
 * "in flight". With TSQ and departure time pacing at lower layers (e.g. fq),
 * we often have several skbs queued in the pacing layer with a pre-scheduled
 * earliest departure time (EDT). BBR adapts its pacing rate based on the
 * inflight level that it estimates has already been "baked in" by previous
 * departure time decisions. We calculate a rough estimate of the number of our
 * packets that might be in the network at the earliest departure time for the
 * next skb scheduled:
 *   in_network_at_edt = inflight_at_edt - (EDT - now) * bw
 * If we're increasing inflight, then we want to know if the transmit of the
 * EDT skb will push inflight above the target, so inflight_at_edt includes
 * bbr_tso_segs_goal() from the skb departing at EDT. If decreasing inflight,
 * then estimate if inflight will sink too low just before the EDT transmit.
 */
static u32 bbr_packets_in_net_at_edt(struct sock *sk, u32 inflight_now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 now_ns, edt_ns, interval_us;
	u32 interval_delivered, inflight_at_edt;

	now_ns = tp->tcp_clock_cache;
	edt_ns = max(tp->tcp_wstamp_ns, now_ns);
	interval_us = div_u64(edt_ns - now_ns, NSEC_PER_USEC);
	interval_delivered = (u64)bbr_bw(sk) * interval_us >> BW_SCALE;
	inflight_at_edt = inflight_now;
	if (bbr->pacing_gain > BBR_UNIT)              /* increasing inflight */
		inflight_at_edt += bbr_tso_segs_goal(sk);  /* include EDT skb */
	if (interval_delivered >= inflight_at_edt)
		return 0;
	return inflight_at_edt - interval_delivered;
}

/* Find the cwnd increment based on estimate of ack aggregation */
static u32 bbr_ack_aggregation_cwnd(struct sock *sk)
{
	u32 max_aggr_cwnd, aggr_cwnd = 0;

	if (bbr_param(sk, extra_acked_gain)) {
		max_aggr_cwnd = ((u64)bbr_bw(sk) * bbr_extra_acked_max_us)
				/ BW_UNIT;
		aggr_cwnd = (bbr_param(sk, extra_acked_gain) * bbr_extra_acked(sk))
			     >> BBR_SCALE;
		aggr_cwnd = min(aggr_cwnd, max_aggr_cwnd);
	}

	return aggr_cwnd;
}

/* Returns the cwnd for PROBE_RTT mode. */
static u32 bbr_probe_rtt_cwnd(struct sock *sk)
{
	return max_t(u32, bbr_param(sk, cwnd_min_target),
		     bbr_bdp(sk, bbr_bw(sk), bbr_param(sk, probe_rtt_cwnd_gain)));
}

/* Slow-start up toward target cwnd (if bw estimate is growing, or packet loss
 * has drawn us down below target), or snap down to target if we're above it.
 */
static void bbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
			 u32 acked, u32 bw, int gain, u32 cwnd,
			 struct bbr_context *ctx)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 target_cwnd = 0;

	if (!acked)
		goto done;  /* no packet fully ACKed; just apply caps */

	target_cwnd = bbr_bdp(sk, bw, gain);

	/* Increment the cwnd to account for excess ACKed data that seems
	 * due to aggregation (of data and/or ACKs) visible in the ACK stream.
	 */
	target_cwnd += bbr_ack_aggregation_cwnd(sk);
	target_cwnd = bbr_quantization_budget(sk, target_cwnd);

	/* Update cwnd and enable fast path if cwnd reaches target_cwnd. */
	bbr->try_fast_path = 0;
	if (bbr_full_bw_reached(sk)) { /* only cut cwnd if we filled the pipe */
		cwnd += acked;
		if (cwnd >= target_cwnd) {
			cwnd = target_cwnd;
			bbr->try_fast_path = 1;
		}
	} else if (cwnd < target_cwnd || cwnd  < 2 * bbr->init_cwnd) {
		cwnd += acked;
	} else {
		bbr->try_fast_path = 1;
	}

	cwnd = max_t(u32, cwnd, bbr_param(sk, cwnd_min_target));
done:
	tcp_snd_cwnd_set(tp, min(cwnd, tp->snd_cwnd_clamp));  /* global cap */
	if (bbr->mode == BBR_PROBE_RTT)  /* drain queue, refresh min_rtt */
		tcp_snd_cwnd_set(tp, min_t(u32, tcp_snd_cwnd(tp),
					   bbr_probe_rtt_cwnd(sk)));
}

static void bbr_reset_startup_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_STARTUP;
}

/* See if we have reached next round trip. Upon start of the new round,
 * returns packets delivered since previous round start plus this ACK.
 */
static u32 bbr_update_round_start(struct sock *sk,
		const struct rate_sample *rs, struct bbr_context *ctx)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 round_delivered = 0;

	bbr->round_start = 0;

	/* See if we've reached the next RTT */
	if (rs->interval_us > 0 &&
	    !before(rs->prior_delivered, bbr->next_rtt_delivered)) {
		round_delivered = tp->delivered - bbr->next_rtt_delivered;
		bbr->next_rtt_delivered = tp->delivered;
		bbr->round_start = 1;
	}
	return round_delivered;
}

/* Calculate the bandwidth based on how fast packets are delivered */
static void bbr_calculate_bw_sample(struct sock *sk,
			const struct rate_sample *rs, struct bbr_context *ctx)
{
	u64 bw = 0;

	/* Divide delivered by the interval to find a (lower bound) bottleneck
	 * bandwidth sample. Delivered is in packets and interval_us in uS and
	 * ratio will be <<1 for most connections. So delivered is first scaled.
	 * Round up to allow growth at low rates, even with integer division.
	 */
	if (rs->interval_us > 0) {
		if (WARN_ONCE(rs->delivered < 0,
			      "negative delivered: %d interval_us: %ld\n",
			      rs->delivered, rs->interval_us))
			return;

		bw = DIV_ROUND_UP_ULL((u64)rs->delivered * BW_UNIT, rs->interval_us);
	}

	ctx->sample_bw = bw;
}

/* Estimates the windowed max degree of ack aggregation.
 * This is used to provision extra in-flight data to keep sending during
 * inter-ACK silences.
 *
 * Degree of ack aggregation is estimated as extra data acked beyond expected.
 *
 * max_extra_acked = "maximum recent excess data ACKed beyond max_bw * interval"
 * cwnd += max_extra_acked
 *
 * Max extra_acked is clamped by cwnd and bw * bbr_extra_acked_max_us (100 ms).
 * Max filter is an approximate sliding window of 5-10 (packet timed) round
 * trips for non-startup phase, and 1-2 round trips for startup.
 */
static void bbr_update_ack_aggregation(struct sock *sk,
				       const struct rate_sample *rs)
{
	u32 epoch_us, expected_acked, extra_acked;
	struct bbr *bbr = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 extra_acked_win_rtts_thresh = bbr_param(sk, extra_acked_win_rtts);

	if (!bbr_param(sk, extra_acked_gain) || rs->acked_sacked <= 0 ||
	    rs->delivered < 0 || rs->interval_us <= 0)
		return;

	if (bbr->round_start) {
		bbr->extra_acked_win_rtts = min(0x1F,
						bbr->extra_acked_win_rtts + 1);
		if (!bbr_full_bw_reached(sk))
			extra_acked_win_rtts_thresh = 1;
		if (bbr->extra_acked_win_rtts >=
		    extra_acked_win_rtts_thresh) {
			bbr->extra_acked_win_rtts = 0;
			bbr->extra_acked_win_idx = bbr->extra_acked_win_idx ?
						   0 : 1;
			bbr->extra_acked[bbr->extra_acked_win_idx] = 0;
		}
	}

	/* Compute how many packets we expected to be delivered over epoch. */
	epoch_us = tcp_stamp_us_delta(tp->delivered_mstamp,
				      bbr->ack_epoch_mstamp);
	expected_acked = ((u64)bbr_bw(sk) * epoch_us) / BW_UNIT;

	/* Reset the aggregation epoch if ACK rate is below expected rate or
	 * significantly large no. of ack received since epoch (potentially
	 * quite old epoch).
	 */
	if (bbr->ack_epoch_acked <= expected_acked ||
	    (bbr->ack_epoch_acked + rs->acked_sacked >=
	     bbr_ack_epoch_acked_reset_thresh)) {
		bbr->ack_epoch_acked = 0;
		bbr->ack_epoch_mstamp = tp->delivered_mstamp;
		expected_acked = 0;
	}

	/* Compute excess data delivered, beyond what was expected. */
	bbr->ack_epoch_acked = min_t(u32, 0xFFFFF,
				     bbr->ack_epoch_acked + rs->acked_sacked);
	extra_acked = bbr->ack_epoch_acked - expected_acked;
	extra_acked = min(extra_acked, tcp_snd_cwnd(tp));
	if (extra_acked > bbr->extra_acked[bbr->extra_acked_win_idx])
		bbr->extra_acked[bbr->extra_acked_win_idx] = extra_acked;
}

static void bbr_check_probe_rtt_done(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	if (!(bbr->probe_rtt_done_stamp &&
	      after(tcp_jiffies32, bbr->probe_rtt_done_stamp)))
		return;

	bbr->min_rtt_stamp = tcp_jiffies32; /* schedule next PROBE_RTT */
	tcp_snd_cwnd_set(tp, max(tcp_snd_cwnd(tp), bbr->prior_cwnd));
	bbr_exit_probe_rtt(sk);
}

/* The goal of PROBE_RTT mode is to have BBR flows cooperatively and
 * periodically drain the bottleneck queue, to converge to measure the true
 * min_rtt (unloaded propagation delay). This allows the flows to keep queues
 * small (reducing queuing delay and packet loss) and achieve fairness among
 * BBR flows.
 *
 * The min_rtt filter window is 10 seconds. When the min_rtt estimate expires,
 * we enter PROBE_RTT mode and cap the cwnd at bbr_cwnd_min_target=4 packets.
 * After at least bbr_probe_rtt_mode_ms=200ms and at least one packet-timed
 * round trip elapsed with that flight size <= 4, we leave PROBE_RTT mode and
 * re-enter the previous mode. BBR uses 200ms to approximately bound the
 * performance penalty of PROBE_RTT's cwnd capping to roughly 2% (200ms/10s).
 *
 * Note that flows need only pay 2% if they are busy sending over the last 10
 * seconds. Interactive applications (e.g., Web, RPCs, video chunks) often have
 * natural silences or low-rate periods within 10 seconds where the rate is low
 * enough for long enough to drain its queue in the bottleneck. We pick up
 * these min RTT measurements opportunistically with our min_rtt filter. :-)
 */
static void bbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	bool min_rtt_expired;
	u32 expire;

	/* Track min RTT seen in the min_rtt_win_sec filter window. This
	 * single window also schedules PROBE_RTT (v1-style), since the
	 * separate probe_rtt_min filter was dropped to fit
	 * ICSK_CA_PRIV_SIZE on stock kernels.
	 */
	expire = bbr->min_rtt_stamp + bbr_param(sk, min_rtt_win_sec) * HZ;
	min_rtt_expired = after(tcp_jiffies32, expire);
	if (rs->rtt_us >= 0 &&
	    (rs->rtt_us < bbr->min_rtt_us ||
	     (min_rtt_expired && !rs->is_ack_delayed))) {
		bbr->min_rtt_us = rs->rtt_us;
		bbr->min_rtt_stamp = tcp_jiffies32;
	}

	if (bbr_param(sk, probe_rtt_mode_ms) > 0 && min_rtt_expired &&
	    !bbr->idle_restart && bbr->mode != BBR_PROBE_RTT) {
		bbr->mode = BBR_PROBE_RTT;  /* dip, drain queue */
		bbr_save_cwnd(sk);  /* note cwnd so we can restore it */
		bbr->probe_rtt_done_stamp = 0;
		bbr->ack_phase = BBR_ACKS_PROBE_STOPPING;
		bbr->next_rtt_delivered = tp->delivered;
	}

	if (bbr->mode == BBR_PROBE_RTT) {
		/* Ignore low rate samples during this mode. */
		tp->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
		/* Maintain min packets in flight for max(200 ms, 1 round). */
		if (!bbr->probe_rtt_done_stamp &&
		    tcp_packets_in_flight(tp) <= bbr_probe_rtt_cwnd(sk)) {
			bbr->probe_rtt_done_stamp = tcp_jiffies32 +
				msecs_to_jiffies(bbr_param(sk, probe_rtt_mode_ms));
			bbr->probe_rtt_round_done = 0;
			bbr->next_rtt_delivered = tp->delivered;
		} else if (bbr->probe_rtt_done_stamp) {
			if (bbr->round_start)
				bbr->probe_rtt_round_done = 1;
			if (bbr->probe_rtt_round_done)
				bbr_check_probe_rtt_done(sk);
		}
	}
	/* Restart after idle ends only once we process a new S/ACK for data */
	if (rs->delivered > 0)
		bbr->idle_restart = 0;
}

static void bbr_update_gains(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	switch (bbr->mode) {
	case BBR_STARTUP:
		bbr->pacing_gain = bbr_param(sk, startup_pacing_gain);
		bbr->cwnd_gain	 = bbr_param(sk, startup_cwnd_gain);
		break;
	case BBR_DRAIN:
		bbr->pacing_gain = bbr_param(sk, drain_gain);  /* slow, to drain */
		bbr->cwnd_gain	 = bbr_param(sk, startup_cwnd_gain);  /* keep cwnd */
		break;
	case BBR_PROBE_BW:
		bbr->pacing_gain = bbr_pacing_gain[bbr->cycle_idx];
		bbr->cwnd_gain	 = bbr_param(sk, cwnd_gain);
		if (bbr_param(sk, bw_probe_cwnd_gain) &&
		    bbr->cycle_idx == BBR_BW_PROBE_UP)
			bbr->cwnd_gain +=
				BBR_UNIT * bbr_param(sk, bw_probe_cwnd_gain) / 4;
		break;
	case BBR_PROBE_RTT:
		bbr->pacing_gain = BBR_UNIT;
		bbr->cwnd_gain	 = BBR_UNIT;
		break;
	default:
		WARN_ONCE(1, "BBR bad mode: %u\n", bbr->mode);
		break;
	}
}

__bpf_kfunc static u32 bbr_sndbuf_expand(struct sock *sk)
{
	/* Provision 3 * cwnd since BBR may slow-start even during recovery. */
	return 3;
}

/* Incorporate a new bw sample into the current window of our max filter. */
static void bbr_take_max_bw_sample(struct sock *sk, u32 bw)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->bw_hi[1] = max(bw, bbr->bw_hi[1]);
}

/* Keep max of last 1-2 cycles. Each PROBE_BW cycle, flip filter window. */
static void bbr_advance_max_bw_filter(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	if (!bbr->bw_hi[1])
		return;  /* no samples in this window; remember old window */
	/* Age the learned max bw slowly instead of dropping it after two
	 * cycles (ZetaTCP-style bandwidth memory). While samples run near
	 * the memory, age 1/16 per cycle; when samples have collapsed below
	 * half of it (a loss episode gutting delivery), hold the memory
	 * (1/64 per cycle) so the episode cannot erase the learned path
	 * capacity -- quick reprobes make cycles RTT-scale, and a 1/16
	 * per-cycle decay would otherwise halve the memory within seconds,
	 * leaving recovery nothing to re-flight to.
	 */
	if (bbr->bw_hi[1] >= bbr->bw_hi[0] >> 1)
		bbr->bw_hi[0] = max(bbr->bw_hi[1],
				    bbr->bw_hi[0] - (bbr->bw_hi[0] >> 4));
	else
		bbr->bw_hi[0] -= bbr->bw_hi[0] >> 6;
	bbr->bw_hi[1] = 0;
	/* Once per PROBE_BW cycle, contribute the converged model to the
	 * path cache so long-lived flows keep the learned state fresh.
	 */
	if (bbr_learning)
		bbr_path_flow_update(sk, false);
}

/* Reset the estimator for reaching full bandwidth based on bw plateau. */
static void bbr_reset_full_bw(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->full_bw = 0;
	bbr->full_bw_cnt = 0;
	bbr->full_bw_now = 0;
}

/* How much do we want in flight? Our BDP, unless congestion cut cwnd. */
static u32 bbr_target_inflight(struct sock *sk)
{
	u32 bdp = bbr_inflight(sk, bbr_bw(sk), BBR_UNIT);

	return min(bdp, tcp_sk(sk)->snd_cwnd);
}

static bool bbr_is_probing_bandwidth(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return (bbr->mode == BBR_STARTUP) ||
		(bbr->mode == BBR_PROBE_BW &&
		 (bbr->cycle_idx == BBR_BW_PROBE_REFILL ||
		  bbr->cycle_idx == BBR_BW_PROBE_UP));
}

/* Has the given amount of time elapsed since we marked the phase start? */
static bool bbr_has_elapsed_in_phase(const struct sock *sk, u32 interval_us)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct bbr *bbr = inet_csk_ca(sk);

	return tcp_stamp_us_delta(tp->tcp_mstamp,
				  bbr->cycle_mstamp + interval_us) > 0;
}

static void bbr_handle_queue_too_high_in_startup(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bdp;  /* estimated BDP in packets, with quantization budget */

	bbr->full_bw_reached = 1;

	bdp = bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT);
	bbr->inflight_hi = max(bdp, bbr->inflight_latest);
}

/* Each round trip of BBR_BW_PROBE_UP, double volume of probing data. */
static void bbr_raise_inflight_hi_slope(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 growth_this_round, cnt;

	/* Calculate "slope": packets S/Acked per inflight_hi increment. */
	growth_this_round = 1 << bbr->bw_probe_up_rounds;
	bbr->bw_probe_up_rounds = min(bbr->bw_probe_up_rounds + 1, 30);
	cnt = tcp_snd_cwnd(tp) / growth_this_round;
	cnt = max(cnt, 1U);
	bbr->bw_probe_up_cnt = cnt;
}

/* In BBR_BW_PROBE_UP, not seeing high loss/ECN/queue, so raise inflight_hi. */
static void bbr_probe_inflight_hi_upward(struct sock *sk,
					  const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 delta;

	if (!tp->is_cwnd_limited || tcp_snd_cwnd(tp) < bbr->inflight_hi)
		return;  /* not fully using inflight_hi, so don't grow it */

	/* For each bw_probe_up_cnt packets ACKed, increase inflight_hi by 1. */
	bbr->bw_probe_up_acks += rs->acked_sacked;
	if (bbr->bw_probe_up_acks >=  bbr->bw_probe_up_cnt) {
		delta = bbr->bw_probe_up_acks / bbr->bw_probe_up_cnt;
		bbr->bw_probe_up_acks -= delta * bbr->bw_probe_up_cnt;
		bbr->inflight_hi += delta;
		bbr->try_fast_path = 0;  /* Need to update cwnd */
	}

	if (bbr->round_start)
		bbr_raise_inflight_hi_slope(sk);
}

/* Does loss/ECN rate for this sample say inflight is "too high"?
 * This is used by both the bbr_check_loss_too_high_in_startup() function,
 * which can be used in either v1 or v2, and the PROBE_UP phase of v2, which
 * uses it to notice when loss/ECN rates suggest inflight is too high.
 */
static bool bbr_is_inflight_too_high(const struct sock *sk,
				      const struct rate_sample *rs)
{
	const struct bbr *bbr = inet_csk_ca(sk);
	u32 loss_thresh, ecn_thresh;

	/* Stock kernels lack the v3 per-skb tx_in_flight accounting, so
	 * approximate the loss rate with the per-ACK sample: packets newly
	 * marked lost vs inflight before this ACK.
	 */
	if (rs->losses > 0 && rs->prior_in_flight) {
		loss_thresh = (u64)rs->prior_in_flight *
			      bbr_loss_thresh_eff(bbr->path_base_loss)
			      >> BBR_SCALE;
		if (rs->losses > (s32)loss_thresh) {
			return true;
		}
	}

	if (rs->delivered_ce > 0 && rs->delivered > 0 &&
	    bbr->ecn_eligible && bbr_param(sk, ecn_thresh)) {
		ecn_thresh = (u64)rs->delivered * bbr_param(sk, ecn_thresh) >>
				BBR_SCALE;
		if (rs->delivered_ce > ecn_thresh) {
			return true;
		}
	}

	return false;
}

/* Classify the current loss signals: return true if the loss looks
 * non-congestive (random/wireless-style drops), i.e. RTT has not inflated
 * toward a standing queue, there are no ECN marks, and the sample loss rate
 * is under noncong_loss_cap. Such loss should not trigger a real backoff
 * (ZetaTCP-style loss discrimination). Note the cap is intentionally looser
 * than loss_thresh: RTT inflation, not loss rate, is the congestion signal.
 *
 * The RTT gate is jitter-adaptive: the soft gate (1.25x min_rtt) is widened
 * by the path's learned loss-free jitter, so jittery last miles do not get
 * their random loss misread as congestion; the widening is capped by the
 * hard gate (1.5x min_rtt), above which loss is always congestive.
 */
static bool bbr_loss_is_noncongestive(struct sock *sk,
				      const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	struct bbr_path_entry pe;
	u32 rtt_us, soft, hard, loss_cap;
	bool have_pe = false;

	if (bbr->min_rtt_us == ~0U)
		return false;	/* no RTT baseline to compare against */
	if (bbr->ecn_in_round || rs->delivered_ce > 0)
		return false;	/* ECN marks indicate real congestion */
	if (bbr_learning) {
		have_pe = bbr_path_peek(sk, &pe);
		/* Refresh the per-socket ambient-loss cache each loss round
		 * (the peek is already paid for), keeping the per-ACK
		 * loss_thresh check lock-free.
		 */
		if (have_pe)
			bbr->path_base_loss = min_t(u32, pe.base_loss, 0x7F);
	}
	if (rs->losses > 0 && rs->prior_in_flight) {
		loss_cap = (u64)rs->prior_in_flight *
			   bbr_param(sk, noncong_loss_cap) >> BBR_SCALE;
		if (rs->losses > (s32)loss_cap)
			return false;	/* loss this dense is risky either way */
	}
	rtt_us = rs->rtt_us > 0 ? rs->rtt_us : tp->srtt_us >> 3;
	if (!rtt_us)
		return false;

	hard = (u64)bbr->min_rtt_us *
	       bbr_param(sk, noncong_rtt_hard) >> BBR_SCALE;
	soft = (u64)bbr->min_rtt_us *
	       bbr_param(sk, noncong_rtt_thresh) >> BBR_SCALE;
	if (have_pe && pe.jitter_us) {
		u32 prior = bbr_prior_from_entry(&pe);

		/* Widen by 1x..3x the learned jitter, scaled by the validated
		 * prior (2x at the neutral point): a path whose verdicts keep
		 * being refuted earns less benefit of the doubt.
		 */
		soft = min(soft + (u32)((u64)pe.jitter_us *
					(BBR_UNIT + 2 * prior) >> BBR_SCALE),
			   hard);
	}
	return rtt_us <= soft;
}

/* If loss/ECN rates during probing indicated we may have overfilled a
 * buffer, return an operating point that tries to leave unutilized headroom in
 * the path for other flows, for fairness convergence and lower RTTs and loss.
 */
static u32 bbr_inflight_with_headroom(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 headroom, headroom_fraction;

	if (bbr->inflight_hi == ~0U)
		return ~0U;

	headroom_fraction = bbr_param(sk, inflight_headroom);
	headroom = ((u64)bbr->inflight_hi * headroom_fraction) >> BBR_SCALE;
	headroom = max(headroom, 1U);
	return max_t(s32, bbr->inflight_hi - headroom,
		     bbr_param(sk, cwnd_min_target));
}

/* Bound cwnd to a sensible level, based on our current probing state
 * machine phase and model of a good inflight level (inflight_lo, inflight_hi).
 */
static void bbr_bound_cwnd_for_inflight_model(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 cap;

	/* tcp_rcv_synsent_state_process() currently calls tcp_ack()
	 * and thus cong_control() without first initializing us(!).
	 */
	if (!bbr->initialized)
		return;

	cap = ~0U;
	if (bbr->mode == BBR_PROBE_BW &&
	    bbr->cycle_idx != BBR_BW_PROBE_CRUISE) {
		/* Probe to see if more packets fit in the path. */
		cap = bbr->inflight_hi;
	} else {
		if (bbr->mode == BBR_PROBE_RTT ||
		    (bbr->mode == BBR_PROBE_BW &&
		     bbr->cycle_idx == BBR_BW_PROBE_CRUISE))
			cap = bbr_inflight_with_headroom(sk);
	}
	/* Adapt to any loss/ECN since our last bw probe. */
	cap = min(cap, bbr->inflight_lo);

	cap = max_t(u32, cap, bbr_param(sk, cwnd_min_target));
	tcp_snd_cwnd_set(tp, min(cap, tcp_snd_cwnd(tp)));
}

/* How should we multiplicatively cut bw or inflight limits based on ECN? */
static u32 bbr_ecn_cut(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return BBR_UNIT -
		((bbr->ecn_alpha * bbr_param(sk, ecn_factor)) >> BBR_SCALE);
}

/* Init lower bounds if have not inited yet. */
static void bbr_init_lower_bounds(struct sock *sk, bool init_bw)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	if (init_bw && bbr->bw_lo == ~0U)
		bbr->bw_lo = bbr_max_bw(sk);
	if (bbr->inflight_lo == ~0U)
		bbr->inflight_lo = tcp_snd_cwnd(tp);
}

/* Reduce bw and inflight to (1 - beta). The caller picks beta: the full cut
 * for congestive loss, or the near-zero cut for non-congestive loss.
 */
static void bbr_loss_lower_bounds(struct sock *sk, u32 *bw, u32 *inflight,
				  u32 beta)
{
	struct bbr* bbr = inet_csk_ca(sk);
	u32 loss_cut = BBR_UNIT - beta;

	*bw = max_t(u32, bbr->bw_latest,
		    (u64)bbr->bw_lo * loss_cut >> BBR_SCALE);
	*inflight = max_t(u32, bbr->inflight_latest,
			  (u64)bbr->inflight_lo * loss_cut >> BBR_SCALE);
}

/* Reduce inflight to (1 - alpha*ecn_factor). */
static void bbr_ecn_lower_bounds(struct sock *sk, u32 *inflight)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 ecn_cut = bbr_ecn_cut(sk);

	*inflight = (u64)bbr->inflight_lo * ecn_cut >> BBR_SCALE;
}

/* Estimate a short-term lower bound on the capacity available now, based
 * on measurements of the current delivery process and recent history. When we
 * are seeing loss/ECN at times when we are not probing bw, then conservatively
 * move toward flow balance by multiplicatively cutting our short-term
 * estimated safe rate and volume of data (bw_lo and inflight_lo). We use a
 * multiplicative decrease in order to converge to a lower capacity in time
 * logarithmic in the magnitude of the decrease.
 *
 * However, we do not cut our short-term estimates lower than the current rate
 * and volume of delivered data from this round trip, since from the current
 * delivery process we can estimate the measured capacity available now.
 *
 * Anything faster than that approach would knowingly risk high loss, which can
 * cause low bw for Reno/CUBIC and high loss recovery latency for
 * request/response flows using any congestion control.
 */
static void bbr_adapt_lower_bounds(struct sock *sk,
				    const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 ecn_inflight_lo = ~0U;
	bool noncong = false;

	/* Classify this round's loss even while probing bw, so that
	 * recovery-exit re-flight decisions never act on a classification
	 * left over from an earlier loss round.
	 */
	if (bbr->loss_in_round) {
		noncong = bbr_loss_is_noncongestive(sk, rs);
		bbr->loss_was_noncong = noncong;
		if (noncong)
			atomic_inc(&bbr_stat_noncong_rounds);
		else
			atomic_inc(&bbr_stat_cong_rounds);
		if (bbr_learning)
			bbr_path_note_loss_round(sk, noncong);
	}

	/* We only use lower-bound estimates when not probing bw.
	 * When probing we need to push inflight higher to probe bw.
	 */
	if (bbr_is_probing_bandwidth(sk))
		return;

	/* ECN response. */
	if (bbr->ecn_in_round && bbr_param(sk, ecn_factor)) {
		bbr_init_lower_bounds(sk, false);
		bbr_ecn_lower_bounds(sk, &ecn_inflight_lo);
	}

	/* Loss response. */
	if (bbr->loss_in_round) {
		bbr_init_lower_bounds(sk, true);
		bbr_loss_lower_bounds(sk, &bbr->bw_lo, &bbr->inflight_lo,
				      noncong ? bbr_noncong_beta_eff(sk) :
						bbr_param(sk, beta));
	}

	/* Adjust to the lower of the levels implied by loss/ECN. */
	bbr->inflight_lo = min(bbr->inflight_lo, ecn_inflight_lo);
	bbr->bw_lo = max(1U, bbr->bw_lo);
}

/* Reset any short-term lower-bound adaptation to congestion, so that we can
 * push our inflight up.
 */
static void bbr_reset_lower_bounds(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->bw_lo = ~0U;
	bbr->inflight_lo = ~0U;
}

/* After bw probing (STARTUP/PROBE_UP), reset signals before entering a state
 * machine phase where we adapt our lower bound based on congestion signals.
 */
static void bbr_reset_congestion_signals(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->loss_in_round = 0;
	bbr->ecn_in_round = 0;
	bbr->loss_in_cycle = 0;
	bbr->ecn_in_cycle = 0;
	bbr->bw_latest = 0;
	bbr->inflight_latest = 0;
}

static void bbr_exit_loss_recovery(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	tcp_snd_cwnd_set(tp, max(tcp_snd_cwnd(tp), bbr->prior_cwnd));
	/* Instant re-flight (ZetaTCP-style): if the loss episode looked
	 * non-congestive, restore rate and volume from the learned path model
	 * immediately instead of ramping back over several round trips.
	 */
	if (bbr->loss_was_noncong && bbr_max_bw(sk)) {
		bbr_reset_lower_bounds(sk);
		tcp_snd_cwnd_set(tp, max(tcp_snd_cwnd(tp),
					 bbr_inflight(sk, bbr_max_bw(sk),
						      bbr_param(sk, cwnd_gain))));
		bbr_set_pacing_rate(sk, bbr_max_bw(sk), BBR_UNIT);
		atomic_inc(&bbr_stat_reflights);
		/* Arm outcome validation: over the next couple of round trips,
		 * check whether delivery holds up near the learned bw
		 * (verdict validated) or collapses (verdict refuted).
		 */
		bbr->reflight_pending = 1;
		bbr->reflight_rounds = 0;
	}
	bbr->try_fast_path = 0; /* bound cwnd using latest model */
}

/* Update rate and volume of delivered data from latest round trip. */
static void bbr_update_latest_delivery_signals(
	struct sock *sk, const struct rate_sample *rs, struct bbr_context *ctx)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->loss_round_start = 0;
	if (rs->interval_us <= 0 || !rs->acked_sacked)
		return; /* Not a valid observation */

	bbr->bw_latest       = max_t(u32, bbr->bw_latest,       ctx->sample_bw);
	bbr->inflight_latest = max_t(u32, bbr->inflight_latest, rs->delivered);

	if (!before(rs->prior_delivered, bbr->loss_round_delivered)) {
		bbr->loss_round_delivered = tp->delivered;
		bbr->loss_round_start = 1;  /* mark start of new round trip */
	}
}

/* Once per round, reset filter for latest rate and volume of delivered data. */
static void bbr_advance_latest_delivery_signals(
	struct sock *sk, const struct rate_sample *rs, struct bbr_context *ctx)
{
	struct bbr *bbr = inet_csk_ca(sk);

	if (bbr->loss_round_start) {
		bbr->bw_latest = ctx->sample_bw;
		bbr->inflight_latest = rs->delivered;
	}
}

/* Update (most of) our congestion signals: track the recent rate and volume of
 * delivered data, presence of loss, and EWMA degree of ECN marking.
 */
static void bbr_update_congestion_signals(
	struct sock *sk, const struct rate_sample *rs, struct bbr_context *ctx)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;

	if (rs->interval_us <= 0 || !rs->acked_sacked)
		return; /* Not a valid observation */
	bw = ctx->sample_bw;

	if (!rs->is_app_limited || bw >= bbr_max_bw(sk))
		bbr_take_max_bw_sample(sk, bw);

	bbr->loss_in_round |= (rs->losses > 0);

	if (!bbr->loss_round_start)
		return;		/* skip the per-round-trip updates */
	/* Now do per-round-trip updates. */
	/* Re-flight outcome validation: two round trips after a noncong
	 * re-flight, score the verdict by whether the last round's delivery
	 * rate still ran near the learned max bw. App-limited rounds prove
	 * nothing either way, so drop the validation rather than mis-score it.
	 * (Entering TCP_CA_Loss scores it refuted, in bbr_set_state().)
	 */
	if (bbr->reflight_pending) {
		if (rs->is_app_limited) {
			bbr->reflight_pending = 0;
		} else if (bbr->reflight_rounds < 2) {
			bbr->reflight_rounds++;
		} else {
			bbr_note_reflight_outcome(sk,
				bbr->bw_latest >= (bbr_max_bw(sk) >> 1));
			bbr->reflight_pending = 0;
		}
	}
	/* Loss-free round: learn this path's baseline RTT jitter
	 * (tp->mdev_us is scaled by 4) for the loss classifier's soft gate.
	 */
	if (bbr_learning && !bbr->loss_in_round && !bbr->ecn_in_round &&
	    tp->mdev_us)
		bbr_path_note_clean_round(sk, tp->mdev_us >> 2);
	/* Sample this round's delivered rate into the path's running mean
	 * (app-limited rounds say nothing about the path). Use the round's
	 * midpoint of the round's max sample and the round-boundary sample:
	 * the boundary sample systematically underestimates (delayed-ACK
	 * stretching; measured -20% vs steady on server1), the round max
	 * systematically overestimates on spike-heavy lossy paths (recovery
	 * ACK batching; measured +53% on server3) -- the two biases cancel
	 * to first order. Skip the STARTUP ramp, whose
	 * climbing rounds only dilute the mean -- unless the flow has already
	 * moved several pipe-fulls, i.e. a stuck plateau detector is the only
	 * reason we still look like STARTUP (round-12 lesson: any gate on a
	 * detector needs a backstop for the detector itself failing).
	 */
	if (bbr_learning && !rs->is_app_limited && bbr->bw_latest &&
	    (bbr->mode != BBR_STARTUP ||
	     tp->delivered >=
		max(4096U, 4 * bbr_bdp(sk, bbr_max_bw(sk), BBR_UNIT))))
		bbr_path_note_round_bw(sk, ctx->sample_bw ?
				       (bbr->bw_latest >> 1) +
				       ((u32)ctx->sample_bw >> 1) :
				       bbr->bw_latest);
	bbr_adapt_lower_bounds(sk, rs);

	bbr->loss_in_round = 0;
	bbr->ecn_in_round  = 0;
}

/* Bandwidth probing can cause loss. To help coexistence with loss-based
 * congestion control we spread out our probing in a Reno-conscious way. Due to
 * the shape of the Reno sawtooth, the time required between loss epochs for an
 * idealized Reno flow is a number of round trips that is the BDP of that
 * flow. We count packet-timed round trips directly, since measured RTT can
 * vary widely, and Reno is driven by packet-timed round trips.
 */
static bool bbr_is_reno_coexistence_probe_time(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 rounds;

	/* Random loss can shave some small percentage off of our inflight
	 * in each round. To survive this, flows need robust periodic probes.
	 */
	rounds = min_t(u32, bbr_param(sk, bw_probe_max_rounds), bbr_target_inflight(sk));
	return bbr->rounds_since_probe >= rounds;
}

/* How long do we want to wait before probing for bandwidth (and risking
 * loss)? We randomize the wait, for better mixing and fairness convergence.
 *
 * We bound the Reno-coexistence inter-bw-probe time to be 62-63 round trips.
 * This is calculated to allow fairness with a 25Mbps, 30ms Reno flow,
 * (eg 4K video to a broadband user):
 *   BDP = 25Mbps * .030sec /(1514bytes) = 61.9 packets
 *
 * We bound the BBR-native inter-bw-probe wall clock time to be:
 *  (a) higher than 2 sec: to try to avoid causing loss for a long enough time
 *      to allow Reno at 30ms to get 4K video bw, the inter-bw-probe time must
 *      be at least: 25Mbps * .030sec / (1514bytes) * 0.030sec = 1.9secs
 *  (b) lower than 3 sec: to ensure flows can start probing in a reasonable
 *      amount of time to discover unutilized bw on human-scale interactive
 *      time-scales (e.g. perhaps traffic from a web page download that we
 *      were competing with is now complete).
 */
static void bbr_pick_probe_wait(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* Decide the random round-trip bound for wait until probe: */
	bbr->rounds_since_probe =
		get_random_u32_below(bbr_param(sk, bw_probe_rand_rounds));
	/* Decide the random wall clock bound for wait until probe: */
	bbr->probe_wait_us = bbr_param(sk, bw_probe_base_us) +
			     get_random_u32_below(bbr_param(sk, bw_probe_rand_us));
}

static void bbr_set_cycle_idx(struct sock *sk, int cycle_idx)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->cycle_idx = cycle_idx;
	/* New phase, so need to update cwnd and pacing rate. */
	bbr->try_fast_path = 0;
}

/* Send at estimated bw to fill the pipe, but not queue. We need this phase
 * before PROBE_UP, because as soon as we send faster than the available bw
 * we will start building a queue, and if the buffer is shallow we can cause
 * loss. If we do not fill the pipe before we cause this loss, our bw_hi and
 * inflight_hi estimates will underestimate.
 */
static void bbr_start_bw_probe_refill(struct sock *sk, u32 bw_probe_up_rounds)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr_reset_lower_bounds(sk);
	bbr->bw_probe_up_rounds = bw_probe_up_rounds;
	bbr->bw_probe_up_acks = 0;
	bbr->stopped_risky_probe = 0;
	bbr->ack_phase = BBR_ACKS_REFILLING;
	bbr->next_rtt_delivered = tp->delivered;
	bbr_set_cycle_idx(sk, BBR_BW_PROBE_REFILL);
}

/* Now probe max deliverable data rate and volume. */
static void bbr_start_bw_probe_up(struct sock *sk, struct bbr_context *ctx)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->ack_phase = BBR_ACKS_PROBE_STARTING;
	bbr->next_rtt_delivered = tp->delivered;
	bbr->cycle_mstamp = tp->tcp_mstamp;
	bbr_reset_full_bw(sk);
	bbr->full_bw = ctx->sample_bw;
	bbr_set_cycle_idx(sk, BBR_BW_PROBE_UP);
	bbr_raise_inflight_hi_slope(sk);
}

/* Start a new PROBE_BW probing cycle of some wall clock length. Pick a wall
 * clock time at which to probe beyond an inflight that we think to be
 * safe. This will knowingly risk packet loss, so we want to do this rarely, to
 * keep packet loss rates low. Also start a round-trip counter, to probe faster
 * if we estimate a Reno flow at our BDP would probe faster.
 */
static void bbr_start_bw_probe_down(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr_reset_congestion_signals(sk);
	bbr->bw_probe_up_cnt = ~0U;     /* not growing inflight_hi any more */
	bbr_pick_probe_wait(sk);
	bbr->cycle_mstamp = tp->tcp_mstamp;		/* start wall clock */
	bbr->ack_phase = BBR_ACKS_PROBE_STOPPING;
	bbr->next_rtt_delivered = tp->delivered;
	bbr_set_cycle_idx(sk, BBR_BW_PROBE_DOWN);
}

/* Cruise: maintain what we estimate to be a neutral, conservative
 * operating point, without attempting to probe up for bandwidth or down for
 * RTT, and only reducing inflight in response to loss/ECN signals.
 */
static void bbr_start_bw_probe_cruise(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	if (bbr->inflight_lo != ~0U)
		bbr->inflight_lo = min(bbr->inflight_lo, bbr->inflight_hi);

	bbr_set_cycle_idx(sk, BBR_BW_PROBE_CRUISE);
}

/* Loss and/or ECN rate is too high while probing.
 * Adapt (once per bw probe) by cutting inflight_hi and then restarting cycle.
 */
static void bbr_handle_inflight_too_high(struct sock *sk,
					  const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 beta = bbr_param(sk, beta);
	bool was_too_high = bbr->prev_probe_too_high;
	bool noncong;

	/* RTT-flat random loss during a probe should not take the full cut:
	 * on a high-ambient-loss path every PROBE_UP sample exceeds
	 * loss_thresh, and a 30% inflight_hi cut per probe cycle would keep
	 * sawing down the ceiling. RTT inflation is the congestion signal.
	 */
	noncong = bbr_loss_is_noncongestive(sk, rs);
	if (noncong)
		beta = bbr_noncong_beta_eff(sk);

	bbr->prev_probe_too_high = 1;
	bbr->bw_probe_samples = 0;  /* only react once per probe */
	/* If we are app-limited then we are not robustly
	 * probing the max volume of inflight data we think
	 * might be safe (analogous to how app-limited bw
	 * samples are not known to be robustly probing bw).
	 */
	if (!rs->is_app_limited) {
		bbr->inflight_hi = max_t(u32, rs->prior_in_flight,
					 (u64)bbr_target_inflight(sk) *
					 (BBR_UNIT - beta) >> BBR_SCALE);
	}
	if (bbr->mode == BBR_PROBE_BW && bbr->cycle_idx == BBR_BW_PROBE_UP) {
		bbr_start_bw_probe_down(sk);
		/* Quick reprobe (ZetaTCP-style): a probe stopped by
		 * non-congestive loss revalidates the ceiling after ~2 round
		 * trips instead of idling out the ~1-1.5s probe wait. The
		 * classifier guarantees min_rtt_us is valid here.
		 *
		 * Only when the previous probe completed cleanly, though: if
		 * probes are being stopped by loss back-to-back (a persistent
		 * loss episode), fall back to the normal probe cadence
		 * instead of slamming a broken pipe with RTT-scale probe
		 * attempts -- each one dumps a fresh burst into heavy loss
		 * and feeds the RTO/backoff spiral that outlives the episode.
		 * A path whose noncong verdicts keep being refuted (prior
		 * below 1/4) loses quick-reprobe privileges entirely; the
		 * round-6 consecutive-failure gate stays absolute regardless
		 * of how good the prior looks.
		 */
		if (noncong && !was_too_high &&
		    bbr_noncong_prior(sk) >= BBR_UNIT / 4) {
			bbr->probe_wait_us =
				min(bbr->probe_wait_us,
				    bbr_param(sk, noncong_reprobe_rtts) *
				    bbr->min_rtt_us);
			atomic_inc(&bbr_stat_quick_reprobes);
		}
	}
}

/* If we're seeing bw and loss samples reflecting our bw probing, adapt
 * using the signals we see. If loss or ECN mark rate gets too high, then adapt
 * inflight_hi downward. If we're able to push inflight higher without such
 * signals, push higher: adapt inflight_hi upward.
 */
static bool bbr_adapt_upper_bounds(struct sock *sk,
				    const struct rate_sample *rs,
				    struct bbr_context *ctx)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* Track when we'll see bw/loss samples resulting from our bw probes. */
	if (bbr->ack_phase == BBR_ACKS_PROBE_STARTING && bbr->round_start)
		bbr->ack_phase = BBR_ACKS_PROBE_FEEDBACK;
	if (bbr->ack_phase == BBR_ACKS_PROBE_STOPPING && bbr->round_start) {
		/* End of samples from bw probing phase. */
		bbr->bw_probe_samples = 0;
		bbr->ack_phase = BBR_ACKS_INIT;
		/* At this point in the cycle, our current bw sample is also
		 * our best recent chance at finding the highest available bw
		 * for this flow. So now is the best time to forget the bw
		 * samples from the previous cycle, by advancing the window.
		 */
		if (bbr->mode == BBR_PROBE_BW && !rs->is_app_limited)
			bbr_advance_max_bw_filter(sk);
		/* If we had an inflight_hi, then probed and pushed inflight all
		 * the way up to hit that inflight_hi without seeing any
		 * high loss/ECN in all the resulting ACKs from that probing,
		 * then probe up again, this time letting inflight persist at
		 * inflight_hi for a round trip, then accelerating beyond.
		 */
		if (bbr->mode == BBR_PROBE_BW &&
		    bbr->stopped_risky_probe && !bbr->prev_probe_too_high) {
			bbr_start_bw_probe_refill(sk, 0);
			return true;  /* yes, decided state transition */
		}
	}
	if (bbr_is_inflight_too_high(sk, rs)) {
		if (bbr->bw_probe_samples)  /*  sample is from bw probing? */
			bbr_handle_inflight_too_high(sk, rs);
	} else {
		/* Loss/ECN rate is declared safe. Adjust upper bound upward. */

		if (bbr->inflight_hi == ~0U)
			return false;   /* no excess queue signals yet */

		/* To be resilient to random loss, we must raise bw/inflight_hi
		 * if we observe in any phase that a higher level is safe.
		 */
		if (rs->prior_in_flight > bbr->inflight_hi) {
			bbr->inflight_hi = rs->prior_in_flight;
		}

		if (bbr->mode == BBR_PROBE_BW &&
		    bbr->cycle_idx == BBR_BW_PROBE_UP)
			bbr_probe_inflight_hi_upward(sk, rs);
	}

	return false;
}

/* Check if it's time to probe for bandwidth now, and if so, kick it off. */
static bool bbr_check_time_to_probe_bw(struct sock *sk,
					const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 n;

	/* If we seem to be at an operating point where we are not seeing loss
	 * but we are seeing ECN marks, then when the ECN marks cease we reprobe
	 * quickly (in case cross-traffic has ceased and freed up bw).
	 */
	if (bbr_param(sk, ecn_reprobe_gain) && bbr->ecn_eligible &&
	    bbr->ecn_in_cycle && !bbr->loss_in_cycle &&
	    inet_csk(sk)->icsk_ca_state == TCP_CA_Open) {
		/* Calculate n so that when bbr_raise_inflight_hi_slope()
		 * computes growth_this_round as 2^n it will be roughly the
		 * desired volume of data (inflight_hi*ecn_reprobe_gain).
		 */
		n = ilog2((((u64)bbr->inflight_hi *
			    bbr_param(sk, ecn_reprobe_gain)) >> BBR_SCALE));
		bbr_start_bw_probe_refill(sk, n);
		return true;
	}

	if (bbr_has_elapsed_in_phase(sk, bbr->probe_wait_us) ||
	    bbr_is_reno_coexistence_probe_time(sk)) {
		bbr_start_bw_probe_refill(sk, 0);
		return true;
	}
	return false;
}

/* Is it time to transition from PROBE_DOWN to PROBE_CRUISE? */
static bool bbr_check_time_to_cruise(struct sock *sk, u32 inflight, u32 bw)
{
	/* Always need to pull inflight down to leave headroom in queue. */
	if (inflight > bbr_inflight_with_headroom(sk))
		return false;

	return inflight <= bbr_inflight(sk, bw, BBR_UNIT);
}

/* PROBE_BW state machine: cruise, refill, probe for bw, or drain? */
static void bbr_update_cycle_phase(struct sock *sk,
				    const struct rate_sample *rs,
				    struct bbr_context *ctx)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	bool is_bw_probe_done = false;
	u32 inflight, bw;

	if (!bbr_full_bw_reached(sk))
		return;

	/* In DRAIN, PROBE_BW, or PROBE_RTT, adjust upper bounds. */
	if (bbr_adapt_upper_bounds(sk, rs, ctx))
		return;		/* already decided state transition */

	if (bbr->mode != BBR_PROBE_BW)
		return;

	inflight = bbr_packets_in_net_at_edt(sk, rs->prior_in_flight);
	bw = bbr_max_bw(sk);

	switch (bbr->cycle_idx) {
	/* First we spend most of our time cruising with a pacing_gain of 1.0,
	 * which paces at the estimated bw, to try to fully use the pipe
	 * without building queue. If we encounter loss/ECN marks, we adapt
	 * by slowing down.
	 */
	case BBR_BW_PROBE_CRUISE:
		if (bbr_check_time_to_probe_bw(sk, rs))
			return;		/* already decided state transition */
		break;

	/* After cruising, when it's time to probe, we first "refill": we send
	 * at the estimated bw to fill the pipe, before probing higher and
	 * knowingly risking overflowing the bottleneck buffer (causing loss).
	 */
	case BBR_BW_PROBE_REFILL:
		if (bbr->round_start) {
			/* After one full round trip of sending in REFILL, we
			 * start to see bw samples reflecting our REFILL, which
			 * may be putting too much data in flight.
			 */
			bbr->bw_probe_samples = 1;
			bbr_start_bw_probe_up(sk, ctx);
		}
		break;

	/* After we refill the pipe, we probe by using a pacing_gain > 1.0, to
	 * probe for bw. If we have not seen loss/ECN, we try to raise inflight
	 * to at least pacing_gain*BDP; note that this may take more than
	 * min_rtt if min_rtt is small (e.g. on a LAN).
	 *
	 * We terminate PROBE_UP bandwidth probing upon any of the following:
	 *
	 * (1) We've pushed inflight up to hit the inflight_hi target set in the
	 *     most recent previous bw probe phase. Thus we want to start
	 *     draining the queue immediately because it's very likely the most
	 *     recently sent packets will fill the queue and cause drops.
	 * (2) If inflight_hi has not limited bandwidth growth recently, and
	 *     yet delivered bandwidth has not increased much recently
	 *     (bbr->full_bw_now).
	 * (3) Loss filter says loss rate is "too high".
	 * (4) ECN filter says ECN mark rate is "too high".
	 *
	 * (1) (2) checked here, (3) (4) checked in bbr_is_inflight_too_high()
	 */
	case BBR_BW_PROBE_UP:
		if (bbr->prev_probe_too_high &&
		    inflight >= bbr->inflight_hi) {
			bbr->stopped_risky_probe = 1;
			is_bw_probe_done = true;
		} else {
			if (tp->is_cwnd_limited &&
			    tcp_snd_cwnd(tp) >= bbr->inflight_hi) {
				/* inflight_hi is limiting bw growth */
				bbr_reset_full_bw(sk);
				bbr->full_bw = ctx->sample_bw;
			} else if (bbr->full_bw_now) {
				/* Plateau in estimated bw. Pipe looks full. */
				is_bw_probe_done = true;
			}
		}
		if (is_bw_probe_done) {
			bbr->prev_probe_too_high = 0;  /* no loss/ECN (yet) */
			bbr_start_bw_probe_down(sk);  /* restart w/ down */
		}
		break;

	/* After probing in PROBE_UP, we have usually accumulated some data in
	 * the bottleneck buffer (if bw probing didn't find more bw). We next
	 * enter PROBE_DOWN to try to drain any excess data from the queue. To
	 * do this, we use a pacing_gain < 1.0. We hold this pacing gain until
	 * our inflight is less then that target cruising point, which is the
	 * minimum of (a) the amount needed to leave headroom, and (b) the
	 * estimated BDP. Once inflight falls to match the target, we estimate
	 * the queue is drained; persisting would underutilize the pipe.
	 */
	case BBR_BW_PROBE_DOWN:
		if (bbr_check_time_to_probe_bw(sk, rs))
			return;		/* already decided state transition */
		if (bbr_check_time_to_cruise(sk, inflight, bw))
			bbr_start_bw_probe_cruise(sk);
		break;

	default:
		WARN_ONCE(1, "BBR invalid cycle index %u\n", bbr->cycle_idx);
	}
}

/* Exiting PROBE_RTT, so return to bandwidth probing in STARTUP or PROBE_BW. */
static void bbr_exit_probe_rtt(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr_reset_lower_bounds(sk);
	if (bbr_full_bw_reached(sk)) {
		bbr->mode = BBR_PROBE_BW;
		/* Raising inflight after PROBE_RTT may cause loss, so reset
		 * the PROBE_BW clock and schedule the next bandwidth probe for
		 * a friendly and randomized future point in time.
		 */
		bbr_start_bw_probe_down(sk);
		/* Since we are exiting PROBE_RTT, we know inflight is
		 * below our estimated BDP, so it is reasonable to cruise.
		 */
		bbr_start_bw_probe_cruise(sk);
	} else {
		bbr->mode = BBR_STARTUP;
	}
}

/* Exit STARTUP based on loss rate > 1% and loss gaps in round >= N. Wait until
 * the end of the round in recovery to get a good estimate of how many packets
 * have been lost, and how many we need to drain with a low pacing rate.
 */
static void bbr_check_loss_too_high_in_startup(struct sock *sk,
						const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	if (bbr_full_bw_reached(sk))
		return;

	/* For STARTUP exit, check the loss rate at the end of each round trip
	 * of Recovery episodes in STARTUP. We check the loss rate at the end
	 * of the round trip to filter out noisy/low loss and have a better
	 * sense of inflight (extent of loss), so we can drain more accurately.
	 */
	if (rs->losses && bbr->loss_events_in_round < 0xf)
		bbr->loss_events_in_round++;  /* update saturating counter */
	if (bbr_param(sk, full_loss_cnt) && bbr->loss_round_start &&
	    inet_csk(sk)->icsk_ca_state == TCP_CA_Recovery &&
	    bbr->loss_events_in_round >= bbr_param(sk, full_loss_cnt) &&
	    bbr_is_inflight_too_high(sk, rs)) {
		bbr_handle_queue_too_high_in_startup(sk);
		return;
	}
	if (bbr->loss_round_start)
		bbr->loss_events_in_round = 0;
}

/* Estimate when the pipe is full, using the change in delivery rate: BBR
 * estimates bw probing filled the pipe if the estimated bw hasn't changed by
 * at least bbr_full_bw_thresh (25%) after bbr_full_bw_cnt (3) non-app-limited
 * rounds. Why 3 rounds: 1: rwin autotuning grows the rwin, 2: we fill the
 * higher rwin, 3: we get higher delivery rate samples. Or transient
 * cross-traffic or radio noise can go away. CUBIC Hystart shares a similar
 * design goal, but uses delay and inter-ACK spacing instead of bandwidth.
 */
static void bbr_check_full_bw_reached(struct sock *sk,
				       const struct rate_sample *rs,
				       struct bbr_context *ctx)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw_thresh, full_cnt, thresh;

	if (bbr->full_bw_now || rs->is_app_limited)
		return;

	thresh = bbr_param(sk, full_bw_thresh);
	full_cnt = bbr_param(sk, full_bw_cnt);
	bw_thresh = (u64)bbr->full_bw * thresh >> BBR_SCALE;
	if (ctx->sample_bw >= bw_thresh) {
		bbr_reset_full_bw(sk);
		bbr->full_bw = ctx->sample_bw;
		return;
	}
	if (!bbr->round_start)
		return;
	++bbr->full_bw_cnt;
	bbr->full_bw_now = bbr->full_bw_cnt >= full_cnt;
	bbr->full_bw_reached |= bbr->full_bw_now;
}

/* If pipe is probably full, drain the queue and then enter steady-state. */
static void bbr_check_drain(struct sock *sk, const struct rate_sample *rs,
			    struct bbr_context *ctx)
{
	struct bbr *bbr = inet_csk_ca(sk);

	if (bbr->mode == BBR_STARTUP && bbr_full_bw_reached(sk)) {
		bbr->mode = BBR_DRAIN;	/* drain queue we created */
		/* Set ssthresh to export purely for monitoring, to signal
		 * completion of initial STARTUP by setting to a non-
		 * TCP_INFINITE_SSTHRESH value (ssthresh is not used by BBR).
		 */
		tcp_sk(sk)->snd_ssthresh =
				bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT);
		bbr_reset_congestion_signals(sk);
	}	/* fall through to check if in-flight is already small: */
	if (bbr->mode == BBR_DRAIN &&
	    bbr_packets_in_net_at_edt(sk, tcp_packets_in_flight(tcp_sk(sk))) <=
	    bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT)) {
		bbr->mode = BBR_PROBE_BW;
		bbr_start_bw_probe_down(sk);
	}
}

static void bbr_update_model(struct sock *sk, const struct rate_sample *rs,
			      struct bbr_context *ctx)
{
	bbr_update_congestion_signals(sk, rs, ctx);
	bbr_update_ack_aggregation(sk, rs);
	bbr_check_loss_too_high_in_startup(sk, rs);
	bbr_check_full_bw_reached(sk, rs, ctx);
	bbr_check_drain(sk, rs, ctx);
	bbr_update_cycle_phase(sk, rs, ctx);
	bbr_update_min_rtt(sk, rs);
}

/* Fast path for app-limited case.
 *
 * On each ack, we execute bbr state machine, which primarily consists of:
 * 1) update model based on new rate sample, and
 * 2) update control based on updated model or state change.
 *
 * There are certain workload/scenarios, e.g. app-limited case, where
 * either we can skip updating model or we can skip update of both model
 * as well as control. This provides signifcant softirq cpu savings for
 * processing incoming acks.
 *
 * In case of app-limited, if there is no congestion (loss/ecn) and
 * if observed bw sample is less than current estimated bw, then we can
 * skip some of the computation in bbr state processing:
 *
 * - if there is no rtt/mode/phase change: In this case, since all the
 *   parameters of the network model are constant, we can skip model
 *   as well control update.
 *
 * - else we can skip rest of the model update. But we still need to
 *   update the control to account for the new rtt/mode/phase.
 *
 * Returns whether we can take fast path or not.
 */
static bool bbr_run_fast_path(struct sock *sk, bool *update_model,
		const struct rate_sample *rs, struct bbr_context *ctx)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 prev_min_rtt_us, prev_mode;

	if (bbr_param(sk, fast_path) && bbr->try_fast_path &&
	    rs->is_app_limited && ctx->sample_bw < bbr_max_bw(sk) &&
	    !bbr->loss_in_round && !bbr->ecn_in_round ) {
		prev_mode = bbr->mode;
		prev_min_rtt_us = bbr->min_rtt_us;
		bbr_check_drain(sk, rs, ctx);
		bbr_update_cycle_phase(sk, rs, ctx);
		bbr_update_min_rtt(sk, rs);

		if (bbr->mode == prev_mode &&
		    bbr->min_rtt_us == prev_min_rtt_us &&
		    bbr->try_fast_path) {
			return true;
		}

		/* Skip model update, but control still needs to be updated */
		*update_model = false;
	}
	return false;
}

__bpf_kfunc static void bbr_main(struct sock *sk, u32 ack, int flag, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	struct bbr_context ctx = { 0 };
	bool update_model = true;
	u32 bw;

	bbr_update_round_start(sk, rs, &ctx);
	if (bbr->round_start)
		bbr->rounds_since_probe =
			min_t(s32, bbr->rounds_since_probe + 1, 0xFF);

	bbr->ecn_in_round  |= (bbr->ecn_eligible && rs->delivered_ce > 0);
	bbr_calculate_bw_sample(sk, rs, &ctx);
	bbr_update_latest_delivery_signals(sk, rs, &ctx);

	if (bbr_run_fast_path(sk, &update_model, rs, &ctx))
		goto out;

	if (update_model)
		bbr_update_model(sk, rs, &ctx);

	bbr_update_gains(sk);
	bw = bbr_bw(sk);
	bbr_set_pacing_rate(sk, bw, bbr->pacing_gain);
	bbr_set_cwnd(sk, rs, rs->acked_sacked, bw, bbr->cwnd_gain,
		     tcp_snd_cwnd(tp), &ctx);
	bbr_bound_cwnd_for_inflight_model(sk);

out:
	bbr_advance_latest_delivery_signals(sk, rs, &ctx);
	bbr->prev_ca_state = inet_csk(sk)->icsk_ca_state;
	bbr->loss_in_cycle |= rs->losses > 0;
	bbr->ecn_in_cycle  |= rs->delivered_ce > 0;
}

__bpf_kfunc static void bbr_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->initialized = 1;

	bbr->init_cwnd = min(0x7FU, tcp_snd_cwnd(tp));
	bbr->prior_cwnd = tp->prior_cwnd;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	bbr->next_rtt_delivered = tp->delivered;
	bbr->prev_ca_state = TCP_CA_Open;

	bbr->probe_rtt_done_stamp = 0;
	bbr->probe_rtt_round_done = 0;
	bbr->min_rtt_us = tcp_min_rtt(tp);
	bbr->min_rtt_stamp = tcp_jiffies32;

	bbr->has_seen_rtt = 0;
	bbr_init_pacing_rate_from_rtt(sk);

	bbr->round_start = 0;
	bbr->idle_restart = 0;
	bbr->full_bw_reached = 0;
	bbr->full_bw = 0;
	bbr->full_bw_cnt = 0;
	bbr->cycle_mstamp = 0;
	bbr->cycle_idx = 0;

	bbr_reset_startup_mode(sk);

	bbr->ack_epoch_mstamp = tp->tcp_mstamp;
	bbr->ack_epoch_acked = 0;
	bbr->extra_acked_win_rtts = 0;
	bbr->extra_acked_win_idx = 0;
	bbr->extra_acked[0] = 0;
	bbr->extra_acked[1] = 0;

	bbr->try_fast_path = 0;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);

	/* Start sampling ECN mark rate after first full flight is ACKed: */
	bbr->loss_round_delivered = tp->delivered + 1;
	bbr->loss_round_start = 0;
	bbr->loss_events_in_round = 0;
	bbr->loss_was_noncong = 0;
	bbr->reflight_pending = 0;
	bbr->reflight_rounds = 0;
	bbr->path_base_loss = 0;
	bbr->startup_ecn_rounds = 0;
	bbr_reset_congestion_signals(sk);
	bbr->bw_lo = ~0U;
	bbr->bw_hi[0] = 0;
	bbr->bw_hi[1] = 0;
	bbr->inflight_lo = ~0U;
	bbr->inflight_hi = ~0U;
	bbr_reset_full_bw(sk);
	bbr->bw_probe_up_cnt = ~0U;
	bbr->bw_probe_up_acks = 0;
	bbr->bw_probe_up_rounds = 0;
	bbr->probe_wait_us = 0;
	bbr->stopped_risky_probe = 0;
	bbr->ack_phase = BBR_ACKS_INIT;
	bbr->rounds_since_probe = 0;
	bbr->bw_probe_samples = 0;
	bbr->prev_probe_too_high = 0;
	bbr->ecn_eligible = 0;
	bbr->ecn_alpha = bbr_param(sk, ecn_alpha_init);

	/* Warm start from the learned path model (ZetaTCP-style): if we have
	 * a fresh bandwidth memory for this destination and the handshake RTT
	 * is consistent with it (same path, plausibly), jump cwnd and pacing
	 * to 75% of the learned operating point so the first flights already
	 * run near path speed. Deliberately do NOT seed the bw model or skip
	 * STARTUP: the flow stays in STARTUP with an empty max-bw filter, so
	 * real delivery samples from the elevated floor still let it discover
	 * the true current capacity with 4x exponential probing. (Seeding the
	 * model and jumping straight to PROBE_BW was tried and anchors flows
	 * at stale estimates: PROBE_UP's multiplicative growth is far slower
	 * than STARTUP, and short flows then write the seed back into the
	 * cache, ratcheting the learned bw downward across generations.)
	 */
	if (bbr_learning && bbr_warm_start &&
	    bbr->min_rtt_us && bbr->min_rtt_us != ~0U) {
		struct bbr_path_entry pe;
		u32 seed_bw = 0;

		if (bbr_path_peek(sk, &pe)) {
			bbr->path_base_loss = min_t(u32, pe.base_loss, 0x7F);
			/* Prefer the running mean of recently delivered
			 * rounds: it already reflects what flows to this
			 * destination actually sustain -- ambient loss and
			 * competing traffic included -- so it needs no
			 * optimism discount. Fall back to the max/plateau
			 * memory, discounted by the learned ambient loss
			 * (that memory runs 2.5-4x optimistic on lossy
			 * paths), when no mean has formed yet.
			 */
			if (pe.bw_avg &&
			    (u32)(tcp_jiffies32 - pe.stamp) <
					bbr_warm_start_max_age_sec * HZ) {
				seed_bw = pe.bw_avg;
			} else if (pe.bw && pe.bw_stamp &&
				   (u32)(tcp_jiffies32 - pe.bw_stamp) <
					bbr_warm_start_max_age_sec * HZ) {
				u32 frac = clamp_t(u32,
						   BBR_UNIT * 3 / 4 -
						   2 * pe.base_loss,
						   BBR_UNIT / 4,
						   BBR_UNIT * 3 / 4);

				seed_bw = (u64)pe.bw * frac >> BBR_SCALE;
			}
			/* Same-path sanity: handshake RTT must be consistent
			 * with the learned min_rtt, else the address likely
			 * moved and the memory is for another path.
			 */
			if (!pe.min_rtt_us ||
			    bbr->min_rtt_us < pe.min_rtt_us / 2 ||
			    bbr->min_rtt_us > pe.min_rtt_us * 4)
				seed_bw = 0;
		}
		if (seed_bw) {
			tcp_snd_cwnd_set(tp,
				min(max(tcp_snd_cwnd(tp),
					bbr_inflight(sk, seed_bw, BBR_UNIT)),
				    tp->snd_cwnd_clamp));
			bbr_set_pacing_rate(sk, seed_bw, BBR_UNIT);
			atomic_inc(&bbr_stat_warm_starts);
		}
	}
}

/* Flow is done: write its learned model back into the path cache so the
 * next connection to this destination does not start from scratch.
 */
__bpf_kfunc static void bbr_release(struct sock *sk)
{
	if (bbr_learning)
		bbr_path_flow_update(sk, true);
}

/* Revert short-term model if current loss recovery event was spurious. */
__bpf_kfunc static u32 bbr_undo_cwnd(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr_reset_full_bw(sk); /* spurious slow-down; reset full bw detector */
	bbr->loss_in_round = 0;
	/* The loss was spurious (e.g. reordering mistaken for loss), so drop
	 * the lower-bound cuts it caused. The per-episode undo_* snapshot was
	 * removed to fit ICSK_CA_PRIV_SIZE; a full reset is the zero-byte
	 * approximation.
	 */
	bbr_reset_lower_bounds(sk);
	bbr->try_fast_path = 0;  /* take slow path to set proper cwnd, pacing */
	return bbr->prior_cwnd;
}

/* Entering loss recovery, so save state for when we undo recovery. */
__bpf_kfunc static u32 bbr_ssthresh(struct sock *sk)
{
	bbr_save_cwnd(sk);
	return tcp_sk(sk)->snd_ssthresh;
}

static size_t bbr_get_info(struct sock *sk, u32 ext, int *attr,
			    union tcp_cc_info *info)
{
	if (ext & (1 << (INET_DIAG_BBRINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct bbr *bbr = inet_csk_ca(sk);
		u64 bw = bbr_bw_bytes_per_sec(sk, bbr_bw(sk));
		struct tcp_bbr_info *bbr_info = &info->bbr;

		memset(bbr_info, 0, sizeof(*bbr_info));
		bbr_info->bbr_bw_lo		= (u32)bw;
		bbr_info->bbr_bw_hi		= (u32)(bw >> 32);
		bbr_info->bbr_min_rtt		= bbr->min_rtt_us;
		bbr_info->bbr_pacing_gain	= bbr->pacing_gain;
		bbr_info->bbr_cwnd_gain		= bbr->cwnd_gain;
		*attr = INET_DIAG_BBRINFO;
		return sizeof(*bbr_info);
	}
	return 0;
}

__bpf_kfunc static void bbr_set_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {

		/* An RTO right after a non-congestive verdict (and/or while a
		 * re-flight was still awaiting validation) is the strongest
		 * evidence the verdict was wrong: score it refuted.
		 */
		if (bbr->prev_ca_state != TCP_CA_Loss &&
		    (bbr->reflight_pending || bbr->loss_was_noncong)) {
			bbr_note_reflight_outcome(sk, false);
			bbr->reflight_pending = 0;
		}
		bbr->prev_ca_state = TCP_CA_Loss;
		/* The tcp_write_timeout() call to sk_rethink_txhash() likely
		 * repathed this flow, so re-learn the min network RTT on the
		 * new path:
		 */
		bbr_reset_full_bw(sk);
		if (!bbr_is_probing_bandwidth(sk) && bbr->inflight_lo == ~0U) {
			/* bbr_adapt_lower_bounds() needs cwnd before
			 * we suffered an RTO, to update inflight_lo:
			 */
			bbr->inflight_lo =
				max(tcp_snd_cwnd(tp), bbr->prior_cwnd);
		}
		/* ZetaTCP-style RTO handling: keep pacing near the learned
		 * rate so SACK-guided retransmits refill the pipe quickly,
		 * instead of draining down to a minimal rate.
		 */
		if (bbr_max_bw(sk))
			bbr_set_pacing_rate(sk, bbr_max_bw(sk), BBR_UNIT);
	} else if (bbr->prev_ca_state == TCP_CA_Loss &&
		   new_state != TCP_CA_Loss) {
		bbr_exit_loss_recovery(sk);
	} else if (inet_csk(sk)->icsk_ca_state == TCP_CA_Recovery &&
		   new_state < TCP_CA_Recovery) {
		/* Exiting fast recovery: re-flight to the learned model
		 * instead of waiting several rounds to regain speed.
		 */
		bbr_exit_loss_recovery(sk);
	}
}


static struct tcp_congestion_ops tcp_bbr_cong_ops __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "bbr_e",
	.owner		= THIS_MODULE,
	.init		= bbr_init,
	.release	= bbr_release,
	.cong_control	= bbr_main,
	.sndbuf_expand	= bbr_sndbuf_expand,
	.undo_cwnd	= bbr_undo_cwnd,
	.cwnd_event	= bbr_cwnd_event,
	.ssthresh	= bbr_ssthresh,
	.min_tso_segs	= bbr_min_tso_segs,
	.get_info	= bbr_get_info,
	.set_state	= bbr_set_state,
};

BTF_KFUNCS_START(tcp_bbr_check_kfunc_ids)
BTF_ID_FLAGS(func, bbr_init)
BTF_ID_FLAGS(func, bbr_release)
BTF_ID_FLAGS(func, bbr_main)
BTF_ID_FLAGS(func, bbr_sndbuf_expand)
BTF_ID_FLAGS(func, bbr_undo_cwnd)
BTF_ID_FLAGS(func, bbr_cwnd_event)
BTF_ID_FLAGS(func, bbr_ssthresh)
BTF_ID_FLAGS(func, bbr_min_tso_segs)
BTF_ID_FLAGS(func, bbr_set_state)
BTF_KFUNCS_END(tcp_bbr_check_kfunc_ids)

static const struct btf_kfunc_id_set tcp_bbr_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &tcp_bbr_check_kfunc_ids,
};

static struct dentry *bbr_debugfs_dir;

static int __init bbr_register(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct bbr) > ICSK_CA_PRIV_SIZE);

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &tcp_bbr_kfunc_set);
	if (ret < 0)
		return ret;
	ret = tcp_register_congestion_control(&tcp_bbr_cong_ops);
	if (ret)
		return ret;

	bbr_path_hash_seed = get_random_u32();
	bbr_debugfs_dir = debugfs_create_dir("tcp_bbr_e", NULL);
	debugfs_create_atomic_t("noncong_loss_rounds", 0444, bbr_debugfs_dir,
				&bbr_stat_noncong_rounds);
	debugfs_create_atomic_t("cong_loss_rounds", 0444, bbr_debugfs_dir,
				&bbr_stat_cong_rounds);
	debugfs_create_atomic_t("recovery_reflights", 0444, bbr_debugfs_dir,
				&bbr_stat_reflights);
	debugfs_create_atomic_t("warm_starts", 0444, bbr_debugfs_dir,
				&bbr_stat_warm_starts);
	debugfs_create_atomic_t("quick_reprobes", 0444, bbr_debugfs_dir,
				&bbr_stat_quick_reprobes);
	debugfs_create_atomic_t("reflight_validated", 0444, bbr_debugfs_dir,
				&bbr_stat_reflight_validated);
	debugfs_create_atomic_t("reflight_refuted", 0444, bbr_debugfs_dir,
				&bbr_stat_reflight_refuted);
	debugfs_create_u32("path_entries", 0444, bbr_debugfs_dir,
			   &bbr_path_entry_cnt);
	debugfs_create_file("paths", 0444, bbr_debugfs_dir, NULL,
			    &bbr_path_fops);
	return 0;
}

static void __exit bbr_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_bbr_cong_ops);
	debugfs_remove_recursive(bbr_debugfs_dir);
	bbr_path_flush();
}

module_init(bbr_register);
module_exit(bbr_unregister);

MODULE_AUTHOR("Van Jacobson <vanj@google.com>");
MODULE_AUTHOR("Neal Cardwell <ncardwell@google.com>");
MODULE_AUTHOR("Yuchung Cheng <ycheng@google.com>");
MODULE_AUTHOR("Soheil Hassas Yeganeh <soheil@google.com>");
MODULE_AUTHOR("Priyaranjan Jha <priyarjha@google.com>");
MODULE_AUTHOR("Yousuk Seung <ysseung@google.com>");
MODULE_AUTHOR("Kevin Yang <yyd@google.com>");
MODULE_AUTHOR("Arjun Roy <arjunroy@google.com>");
MODULE_AUTHOR("David Morley <morleyd@google.com>");

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP BBR_E (BBRv3-based, ZetaTCP-style loss handling)");
MODULE_VERSION(__stringify(BBR_VERSION));
