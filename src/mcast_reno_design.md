# Multicast TCP Reno Transport — Design & Test Guide

> **Files:** `src/mcast_reno_sender_updated.cpp` · `src/mcast_reno_receiver_updated.cpp`
>
> These supersede the original `mcast_reno_sender.cpp` / `mcast_reno_receiver.cpp`.
> See §3 for a precise diff of every change.

---

## 1. Overview

This transport delivers a byte stream reliably from one sender to a static cohort
of receivers over UDP multicast, on a trusted LAN.  It adapts TCP Reno congestion
control to the one-to-many topology with three key departures from standard Reno:

| Mechanism | Standard TCP Reno | Multicast adaptation |
|---|---|---|
| `snd_una` advance | On new ACK from receiver | Only when **all** cohort receivers ACK past that seq |
| `cwnd` growth | Every new ACK | Only on the **first** receiver ACK per slot (not on retransmit ACKs) |
| Fast-retransmit trigger | 3 dup-ACKs from one receiver | ≥ X% of cohort each send ≥ 1 dup-ACK within T_agg window |
| Fast-recovery exit | First new ACK | `committed_una` > `recovery_point` — all receivers confirmed |

---

## 2. Current Design

### 2.1 Wire Format

Every packet begins with a **22-byte `RmHeader`** (packed, no padding):

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          seq (32)                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         src_port (16)         |          flags (16)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| retrans_id(8) | reserved (8)  |          window (16)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          checksum (16)        |            (padding)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         tsval (32)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         tsecr (32)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

All multi-byte fields are in **network byte order**.

| Field | Description |
|---|---|
| `seq` | Segment index (1-based). SYN/START use 0. FIN uses `total_segments + 1`. |
| `src_port` | Sender's bound UDP port — receivers unicast ACKs back here. |
| `flags` | `SYN=0x01  ACK=0x02  START=0x04  DATA=0x08  FIN=0x10  RST=0x20` |
| `retrans_id` | Retransmission epoch (1–8). Incremented on every retransmit of a slot. Echoed by receivers so the sender can filter stale ACKs. |
| `reserved` | Must be zero. |
| `window` | Advertised receive window in segments. Sender always sends 1. Receivers send remaining OOO buffer headroom. |
| `checksum` | Internet checksum over the 22-byte header only (not the payload). |
| `tsval` | Sender wall-clock milliseconds. Used for RTT estimation. |
| `tsecr` | Echoed `tsval` — the receiver copies it back so the sender can measure RTT. Karn's algorithm: only sampled on non-retransmit ACKs. |

---

### 2.2 Session Lifecycle

```
Sender                                   Receivers (multicast group)
  │
  │── SYN (seq=0, tsval=T) ──────────────────────────────────►│
  │◄────────────────────────────── SYN|ACK (tsecr=T) ─────────│  (one per receiver)
  │   repeat until --expected receivers respond
  │
  │── START (seq=0) ──────────────────────────────────────────►│
  │
  │          ┌─ data transfer (sliding window, §2.4) ─┐
  │          └────────────────────────────────────────┘
  │
  │── FIN (seq=total+1) ─────────────────────────────────────►│
  │◄───────────────────────────── ACK (seq=fin_seq) ───────────│  (one per receiver)
  │   repeat until all receivers ACK
```

**Implicit START:** if a DATA or FIN packet arrives at a receiver before START
(multicast loss), the receiver infers START was lost and enters data phase.

**Retransmit IDs:** handshake retries increment `retrans_id` from 1 to 8.
A receiver echoes the `retrans_id` from the packet it ACKs, allowing the
sender to discard SYN|ACK replies from stale handshake rounds.

---

### 2.3 Sender — Three-Component Architecture

#### Component 1 — AckWindow / AckSlot

A hash map `seq → AckSlot` covering the in-flight range `[snd_una, snd_nxt)`.
All access is under `AckAggState::mtx`.  No per-receiver state lives here.

```
AckSlot {
    ack_count         // # receivers that ACKed past this seq in the current epoch
    first_ack_done    // true once ack_count went 0→1, OR after a retransmit
                      //   (suppresses cwnd growth on retransmit ACKs, per spec §7)
    dup_ack_senders   // set of peer_keys that sent ≥1 dup-ACK within T_agg
    dup_ack_count     // == dup_ack_senders.size()
    dupack_window_open/start  // T_agg timer state
    retrans_id        // current epoch
    is_retransmit     // true if most recent tx was a retransmit (blocks RTT sampling)
}
```

**`mark_retransmit(seq, new_retrans_id)`** — called on every retransmit:
- `ack_count = 0` — all receivers must re-ACK in the new epoch
- `first_ack_done = true` — ACKs for this retransmit do NOT grow cwnd
- Clears all dup-ACK state so T_agg opens fresh for the new epoch

**`erase_below(committed_una)`** — removes fully committed slots.

---

#### Component 2 — RenoSM (Reno State Machine)

Lives entirely in the main thread — no locking required.
Consumes only aggregated events from Component 3.

**States:** `SLOW_START` → `CONG_AVOIDANCE` ↔ `FAST_RECOVERY`

| Event | Trigger | Action |
|---|---|---|
| `on_first_ack(n)` | n slots got their first receiver ACK | SS: `cwnd += n`; CA: `cwnd += n/cwnd`; FR: `cwnd += n` (window inflation) |
| `on_dup_ack_threshold(seq)` | X% of cohort dup-ACKed seq | If not in FR: `ssthresh = max(cwnd/2,2)`, `cwnd = ssthresh+3`, enter FR. Always: `recovery_point = max(recovery_point, seq)` |
| `on_recovery_ack()` | `committed_una > recovery_point` while in FR | `cwnd = ssthresh`, enter CA |
| `on_partial_ack(n)` | `committed_una` advanced but not past `recovery_point` | `cwnd -= n; cwnd += 1; clamp ≥ 1`. Immediately retransmit next unACKed segment. |
| `on_timeout()` | RTO expired | `ssthresh = max(cwnd/2,2)`, `cwnd = 1`, enter SS |

**RTT estimation** (Jacobson/Karels, RFC 6298):
```
first sample:  srtt = sample;  rttvar = sample/2
later:         rttvar = 0.75*rttvar + 0.25*|sample - srtt|
               srtt   = 0.875*srtt  + 0.125*sample
               rto    = clamp(srtt + 4*rttvar, 10ms, 30s)
```

**Effective send window:** `min(reno.window_size(), min_rwnd)` — the
most-constrained receiver's advertised buffer size caps the CC window.

---

#### Component 3 — ACK Aggregator Thread

Polls the socket (10 ms poll interval via `select`).
For each valid cohort ACK (verified by `is_cohort_member` + checksum):

**Flow control** (runs first, before the forward-progress/dup split):
- Updates `peer_rwnd[peer_key]` from `rh.window`
- Recomputes `min_rwnd = min(peer_rwnd)` across all peers
- Notifies the main-thread CV if `min_rwnd` changed

**Forward-progress path** (`cum_ack > peer_prev`):

1. **Stale-epoch filter:** if `pkt_rid < slot[cum_ack-1].retrans_id` → discard.
   Prevents old-epoch ACKs from counting in a new retransmit epoch.
2. Credit `ack_count` for every slot in `[peer_prev, cum_ack)`.
   If `!first_ack_done` → set it, increment `first_ack_count` signal.
3. Update `peer_cum_ack[peer_key] = cum_ack`.
4. **Advance `committed_una`:** walk forward from `committed_una` while
   `slot.ack_count >= cohort.size()`. Signals main thread on advance.
5. **RTT sample (Karn's):** if `slot[cum_ack-1].is_retransmit == false`,
   record `last_tsecr` for main thread to use.

**Dup-ACK path** (`cum_ack == peer_prev`):

1. **Stale-epoch filter:** if `pkt_rid < slot[peer_prev].retrans_id` → discard.
2. **T_agg timer:**
   - First dup-ACK for this slot → open T_agg window.
   - Subsequent dup-ACK within window → count it.
   - After window expires → **reset** sender set and start a new window
     (sustained loss accumulates dup-ACKs across multiple T_agg periods).
3. Insert `peer_key` into `dup_ack_senders`. If
   `dup_ack_count >= fr_threshold AND !fast_retransmit_needed AND !is_retransmit`
   → set `fast_retransmit_needed`.

---

### 2.4 Sender — Main Loop (`transfer`)

```
loop:
  if committed_una > total → done

  eff_wnd = min(cwnd, min_rwnd)
  while snd_nxt ≤ total AND snd_nxt < committed + eff_wnd:
      add_slot(snd_nxt)          ← slot created BEFORE sendto (no ACK-before-slot race)
      send_segment(snd_nxt)
      snd_nxt++

  if in_flight.empty() → break   ← safety guard against UB dereference

  wait on CV until:
      committed_una advanced  OR  first_ack event  OR
      fast_retransmit needed  OR  min_rwnd changed
      (or RTO of oldest in-flight packet expires)

  drain signals under lock (first_ack_count, fast_retransmit_seq, tsecr)

  if RTT sample available → update Jacobson/Karels estimator

  if first_ack_events > 0:
      reno.on_first_ack(n)

  if committed_una advanced:
      erase committed slots from in_flight and AckWindow
      if rto_reset_on_ack → rto_ms = current RTT estimate
      if in FR AND committed_una > recovery_point → on_recovery_ack()
      else if in FR → on_partial_ack(newly_acked); retransmit next unACKed
      else → log COMMIT

  if fast_retransmit AND seq still in flight:
      on_dup_ack_threshold(seq)
      retransmit_segment(seq)
      mark_retransmit(seq, new_retrans_id)

  if timeout (CV returned false, woke_up==false):
      consec_timeouts++; if > retries → abort
      on_timeout()
      rto_ms = min(rto_ms*2, 30s)
      retransmit_segment(prev_committed)
      mark_retransmit(prev_committed, new_retrans_id)
```

---

### 2.5 Receiver

One socket bound to `INADDR_ANY:port`, joined to the multicast group.
State: `rcv_nxt` (next expected seq) + `ooo_buf` (map of buffered OOO segments).

Each `OooBufEntry` stores `{payload, tsval, retrans_id}` so the cumulative ACK
after an OOO drain echoes the last delivered segment (not the triggering packet).

| Incoming case | Action |
|---|---|
| `seq == rcv_nxt` (in-order) | Deliver; `rcv_nxt++`; drain contiguous OOO; cumulative ACK echoing tsval/retrans_id of the **last** drained entry |
| `seq > rcv_nxt` (OOO) | Buffer if space; dup-ACK (`seq=rcv_nxt`) echoing `last_inorder_retrans_id` — **not** the OOO packet's epoch |
| `seq < rcv_nxt` (duplicate) | Re-ACK with `rcv_nxt` and `last_inorder_retrans_id` |
| FIN | Flush OOO buffer; ACK with `seq=fin_seq` (echo style, NOT cumulative, for compatibility with sender's `wait_all_acks`) |

**Why `last_inorder_retrans_id` for dup-ACKs:**
The sender's dup-ACK epoch filter checks `slot[peer_prev].retrans_id`, which
corresponds to the *lost* packet.  Echoing an OOO packet's retrans_id (which
belongs to a different, unrelated slot) would confuse the filter and cause
legitimate dup-ACKs to be discarded.

**`--ack-drop-rate P`:** randomly drops forward-progress ACKs with
probability P (0.0–1.0). For fault-injection testing only.

---

### 2.6 Key Invariants

1. **`committed_una` advance** requires `ack_count >= cohort.size()` for
   every slot up to the new frontier, *in the current epoch* (stale-epoch
   filter blocks old-epoch ACKs from satisfying this).

2. **cwnd growth** fires only once per slot per epoch (via `first_ack_done`).
   After a retransmit, `first_ack_done` is set to `true` immediately by
   `mark_retransmit`, suppressing cwnd growth on retransmit ACKs.

3. **Fast-recovery exit** waits for `committed_una > recovery_point` — every
   receiver must have confirmed the lost packet.

4. **`add_slot` before `sendto`** eliminates the race where an ACK arrives
   and is processed by the aggregator before the slot exists in the AckWindow.

5. **T_agg reset on expiry** means sustained loss over multiple T_agg periods
   still accumulates dup-ACKs and can trigger fast retransmit.

---

## 3. What Changed from the Original (`mcast_reno_sender.cpp` → `_updated`)

### 3.1 Bugs Fixed

#### Fix 1 — `add_slot` before `send_segment` (critical race condition)

**Original:** slot was added to AckWindow *after* the packet was sent.
```cpp
// BEFORE (wrong order — ACK can arrive before slot exists)
if (!send_segment(snd_nxt)) return false;
agg.ack_wnd.add_slot(snd_nxt, 1);
```
**Fixed:**
```cpp
// AFTER (slot exists before ACK can possibly arrive)
agg.ack_wnd.add_slot(snd_nxt, 1);
if (!send_segment(snd_nxt)) return false;
```
On a fast LAN an ACK can loop back before the main thread reaches `add_slot`.
The aggregator calls `ack_wnd.get(seq)` → `nullptr`, silently discards the ACK,
and `committed_una` stalls forever for that slot.

---

#### Fix 2 — `ack_count` and `first_ack_done` not reset on retransmit (critical)

**Original:** `mark_retransmit` reset both to 0/false.
**Updated (broken):** both lines were commented out — neither reset nor set.
```cpp
// BROKEN intermediate state
// s.ack_count      = initial_ack_count;   ← commented out
// s.first_ack_done = (initial_ack_count > 0);  ← commented out
```
**Fixed:**
```cpp
s.ack_count      = 0;     // all receivers must re-ACK the new epoch
s.first_ack_done = true;  // suppress cwnd growth on retransmit ACKs (spec §7)
```
Without this fix: `ack_count` retained its pre-retransmit value causing
`committed_una` to advance on a mix of old-epoch and new-epoch ACKs;
`first_ack_done` stuck at `true` meant cwnd never grew after a retransmit.

The intermediate version also introduced a dead `already_acked_count` lambda
that was computed and passed to `mark_retransmit` but never used — removed.

---

#### Fix 3 — Forward-progress stale-epoch filter removed (correctness)

**Original:**
```cpp
if (cum_ack > 0) {
    const AckSlot* chk = agg.ack_wnd.get(cum_ack - 1);
    if (chk && pkt_rid < chk->retrans_id) continue; // stale
}
```
**Updated (broken):** this entire block was commented out with `/* ... */`.

Without it, a delayed old-epoch ACK arriving after a retransmit still
increments `ack_count`, potentially pushing `committed_una` forward based on
a mix of stale and current-epoch acknowledgements — violating the reliability
guarantee.  **Restored.**

---

#### Fix 4 — `in_flight.empty()` crash guard removed

**Original:**
```cpp
if (in_flight.empty()) break; // safety
```
**Updated (broken):** replaced with a commented-out version; the next line
`auto& oldest = in_flight.begin()->second` dereferences `end()` if
`in_flight` is empty — undefined behaviour / crash.  **Restored.**

---

#### Fix 5 — `srand()` called twice in receiver (minor)

`parse_args` had a misplaced `srand(time(nullptr))` tacked onto its closing
brace (no newline, same line as `return true`), and `run()` called it again.
Removed the one in `parse_args`.  Added missing `<cstdlib>` / `<ctime>` includes.

---

#### Fix 6 — `--ack-drop-rate` missing from usage string (minor)

The new flag was parsed but not documented in `usage()`.  Added.

---

### 3.2 Improvements Kept from the Updated Version

These were correct changes made by the other agent:

| Change | Why it's correct |
|---|---|
| `is_retransmit` guard on fast-retransmit trigger | Prevents re-triggering FR for a slot already being retransmitted, avoiding repeated retransmit storms |
| T_agg window **resets** on expiry (instead of just discarding) | Sustained loss over multiple T_agg periods can still accumulate dup-ACKs and trigger fast retransmit |
| `min_rwnd` change notifies CV | Main thread wakes immediately when a slow receiver drains its buffer, instead of waiting for the next RTO |
| `committed_una` uses AckWindow `ack_count` walk (not `min(peer_cum_ack)`) | Correct when paired with Fixes 2+3; more direct — committed_una is exactly where all receivers are confirmed |
| `--ack-drop-rate` receiver flag | Fault-injection for testing without real network impairment |

---

## 4. Building

```bash
# Sender
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -pthread \
    -o mcast_reno_sender src/mcast_reno_sender_updated.cpp

# Receiver
g++ -std=c++17 -O2 -Wall -Wextra -pedantic \
    -o mcast_reno_receiver src/mcast_reno_receiver_updated.cpp
```

**Expected output:** two warnings only (backslash continuation in comment
block examples) — no errors, no real warnings.

**Platform:** Linux only (uses `AF_INET SOCK_DGRAM` multicast, `IP_ADD_MEMBERSHIP`,
`select`, `pthreads`).  Build in WSL or a Linux VM on Windows.

---

## 5. Running the Tests

### Prerequisites

```bash
# Get your interface IP (use this as --iface for all commands below)
IFACE=$(ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
echo $IFACE
```

All commands below use:
- Multicast group: `239.255.0.1`
- Multicast port: `5000`
- Sender ACK port: `45000`

---

### Test 1 — Happy path, single receiver

**What it checks:** full session lifecycle, slow start, congestion avoidance,
fast retransmit, fast recovery entry/exit, FIN teardown, byte-perfect delivery.

```bash
# Terminal 1 — receiver
./mcast_reno_receiver \
    --group 239.255.0.1 --port 5000 --iface $IFACE \
    --out /tmp/recv.bin --ooo-buf 64

# Terminal 2 — generate payload and run sender
dd if=/dev/urandom of=/tmp/payload.bin bs=1K count=64
./mcast_reno_sender \
    --group 239.255.0.1 --port 5000 --sender-port 45000 --expected 1 \
    --iface $IFACE --ttl 1 --file /tmp/payload.bin \
    --rto-ms 100 --retries 20 --dupack-pct 50 --tagg-ms 50

# Verify
diff /tmp/payload.bin /tmp/recv.bin && echo "PASS: byte-perfect match"
```

**Expected sender log events:**
```
Handshake complete in ...
FIRST_ACK ×N cwnd=... state=SS     ← slow start: cwnd doubling
COMMIT committed=... state=SS/CA
FAST_RETRANSMIT seq=...             ← at least once on loopback (buffering artefacts)
EXIT FR committed=...               ← clean recovery exit
Transfer complete. Sending FIN.
All receivers ACKed FIN. Done.
```

**Note for same-host testing:** the sender sets `IP_MULTICAST_LOOP=0` to
prevent itself receiving its own multicast — but on Linux this also prevents
other processes on the same host receiving it.  For local tests, rebuild with
`int loop = 1;` in `McastRenoSender::init()`, or use the netns setup in Test 3.

---

### Test 2 — Fault injection: ACK drops

**What it checks:** RTO timeout recovery, robustness under ACK loss,
correct byte delivery despite missing acknowledgements.

```bash
# Terminal 1 — receiver drops 40% of forward-progress ACKs
./mcast_reno_receiver \
    --group 239.255.0.1 --port 5000 --iface $IFACE \
    --out /tmp/recv_lossy.bin --ooo-buf 64 \
    --ack-drop-rate 0.4

# Terminal 2 — sender (longer RTO to survive drops)
dd if=/dev/urandom of=/tmp/payload.bin bs=1K count=64
./mcast_reno_sender \
    --group 239.255.0.1 --port 5000 --sender-port 45000 --expected 1 \
    --iface $IFACE --ttl 1 --file /tmp/payload.bin \
    --rto-ms 150 --retries 30 --dupack-pct 50 --tagg-ms 50

# Verify
diff /tmp/payload.bin /tmp/recv_lossy.bin && echo "PASS: byte-perfect despite ACK drops"
```

**Expected sender log events:**
```
[DROP] ACK seq=N retrans_id=1       ← from receiver stderr
RTO timeout committed=...            ← sender retransmits oldest unACKed
-> RETRANSMIT seq=N retrans_id=2
FIRST_ACK ×1 cwnd=... state=CA      ← recovery, cwnd restarts from CA
```

Try different drop rates: `0.1`, `0.3`, `0.5`.  At `0.5` with a single
receiver the dupack threshold (50% of 1 = 1 receiver) will also fire,
mixing RTO and fast-retransmit recovery paths.

---

### Test 3 — Multi-receiver, two separate IPs (requires `sudo`)

Single-host multi-receiver testing requires separate IPs so the sender's
`PeerKey{ip,port}` distinguishes the two receivers.  Use network namespaces:

```bash
# ── Setup (run once) ─────────────────────────────────────────
sudo ip netns add ns_a
sudo ip netns add ns_b
sudo ip link add veth_a type veth peer name veth_a_br
sudo ip link add veth_b type veth peer name veth_b_br
sudo ip link add br0 type bridge
sudo ip link set veth_a_br master br0
sudo ip link set veth_b_br master br0
sudo ip link set veth_a netns ns_a
sudo ip link set veth_b netns ns_b
sudo ip netns exec ns_a ip addr add 10.99.0.2/24 dev veth_a
sudo ip netns exec ns_b ip addr add 10.99.0.3/24 dev veth_b
sudo ip addr add 10.99.0.1/24 dev br0
sudo ip link set br0 up
sudo ip link set veth_a_br up; sudo ip link set veth_b_br up
sudo ip netns exec ns_a ip link set veth_a up
sudo ip netns exec ns_b ip link set veth_b up

# ── Run test ─────────────────────────────────────────────────
dd if=/dev/urandom of=/tmp/payload.bin bs=256K count=1

# Receiver A in ns_a
sudo ip netns exec ns_a ./mcast_reno_receiver \
    --group 239.255.0.1 --port 5000 --iface 10.99.0.2 \
    --out /tmp/recv_a.bin --ooo-buf 64 &

# Receiver B in ns_b
sudo ip netns exec ns_b ./mcast_reno_receiver \
    --group 239.255.0.1 --port 5000 --iface 10.99.0.3 \
    --out /tmp/recv_b.bin --ooo-buf 64 &

sleep 0.5

# Sender on the bridge (no loop=1 needed — different interfaces)
./mcast_reno_sender \
    --group 239.255.0.1 --port 5000 --sender-port 45000 --expected 2 \
    --iface 10.99.0.1 --ttl 2 --file /tmp/payload.bin \
    --rto-ms 100 --retries 20 --dupack-pct 50 --tagg-ms 50

# Verify both
diff /tmp/payload.bin /tmp/recv_a.bin && echo "PASS A"
diff /tmp/payload.bin /tmp/recv_b.bin && echo "PASS B"

# ── Teardown ─────────────────────────────────────────────────
sudo ip netns del ns_a
sudo ip netns del ns_b
sudo ip link del br0
```

**What this adds over Test 1:**
- `committed_una` only advances when BOTH receivers ACK → real multi-receiver
  semantics
- A slow receiver (add `sleep 0.01` in receiver B's `run()` loop, or use
  `tc netem delay 20ms` in `ns_b`) creates back-pressure via `min_rwnd`

---

### Test 4 — Sub-threshold loss (no cwnd reduction)

**What it checks:** with 2 receivers and `--dupack-pct 80`, loss on only 1
receiver (< 80%) should NOT trigger fast retransmit — RTO recovers it silently.

```bash
# Using the netns setup from Test 3:

# Receiver A — normal
sudo ip netns exec ns_a ./mcast_reno_receiver \
    --group 239.255.0.1 --port 5000 --iface 10.99.0.2 --out /tmp/recv_a.bin &

# Receiver B — drops 60% of ACKs (one receiver out of two = 50% < 80% threshold)
sudo ip netns exec ns_b ./mcast_reno_receiver \
    --group 239.255.0.1 --port 5000 --iface 10.99.0.3 \
    --out /tmp/recv_b.bin --ack-drop-rate 0.6 &

sleep 0.5

./mcast_reno_sender \
    --group 239.255.0.1 --port 5000 --sender-port 45000 --expected 2 \
    --iface 10.99.0.1 --ttl 2 --file /tmp/payload.bin \
    --rto-ms 200 --retries 30 --dupack-pct 80 --tagg-ms 100
```

**Expected:** sender log shows **no** `FAST_RETRANSMIT` lines; only `RTO timeout`
lines when ACK drops cause timeouts.  `committed_una` is held back by receiver B
until it eventually delivers all segments via RTO retransmits.

---

### Test 5 — Epoch filter: stale ACK after retransmit

**What it checks:** a delayed old-epoch ACK arriving after a retransmit does
NOT advance `committed_una` on its own.

This is hard to inject artificially but is implicitly exercised in Tests 2–4
whenever a retransmit fires and a late ACK arrives shortly after.  To verify
explicitly: look for `-> RETRANSMIT seq=N retrans_id=2` in the sender log
followed by `EXIT FR committed=M` only after the receiver sends a fresh ACK
(i.e., `committed` advances to M only after the retransmit, not before).

---

### Test 6 — Large file transfer

**What it checks:** no memory leaks or slot accounting bugs over thousands
of segments.

```bash
dd if=/dev/urandom of=/tmp/large.bin bs=1M count=10   # 10 MB

./mcast_reno_sender \
    --group 239.255.0.1 --port 5000 --sender-port 45000 --expected 1 \
    --iface $IFACE --ttl 1 --file /tmp/large.bin \
    --rto-ms 100 --retries 20 --dupack-pct 50 --tagg-ms 50 \
    --chunk 1400

diff /tmp/large.bin /tmp/recv.bin && echo "PASS: 10 MB match"
```

---

## 6. Interpreting the Sender Log

| Log line | Meaning |
|---|---|
| `FIRST_ACK ×N cwnd=X state=SS/CA/FR` | N slots got their first ACK → cwnd updated |
| `COMMIT committed=N cwnd=X state=CA` | All receivers ACKed past N; `snd_una` advanced |
| `FAST_RETRANSMIT seq=N cwnd=X ssthresh=Y state=FR` | Entered fast recovery for slot N |
| `EXIT FR committed=N cwnd=X state=CA` | Exited fast recovery; all receivers past recovery_point |
| `PARTIAL_ACK committed=N newly_acked=K retransmit seq=M` | committed advanced but still in FR; retransmitting next unACKed |
| `FAST_RETRANSMIT seq=N already committed — skipping FR entry` | Stale signal; slot already committed before main thread processed it |
| `RTO timeout committed=N cwnd=1 new_rto=Xms` | RTO fired; slow start; retransmitting oldest unACKed |
| `RTT sample=Nms srtt=X rto=Yms` | RTT sample recorded (Karn's: from non-retransmit ACK only) |

---

## 7. Known Limitations for Local Testing

1. **`IP_MULTICAST_LOOP=0`** is set by the sender to avoid receiving its own
   multicast.  On Linux this also prevents other processes on the **same host**
   from receiving it.  For same-host testing, rebuild with `loop=1` in
   `McastRenoSender::init()`.

2. **Same-host, same-port PeerKey collision:** two receivers on the same machine
   both bind to port 5000; both SYN|ACKs come from `<host_ip>:5000`, so the
   sender sees only one cohort member.  Requires the `ip netns` setup (Test 3)
   or two physical machines.

3. **Zero RTT on loopback:** loopback RTT is < 1 ms, so the RTT estimator
   clamps to the 10 ms minimum and RTO stays at 10 ms.  This makes RTO
   behaviour look different from a real LAN.  This is expected.
