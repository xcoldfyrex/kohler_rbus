# Kohler RBUS Protocol — Reverse Engineering Notes

This is my attempt at reverse engineering the Kohler RBUS protocol for integration into my own smarthome software and 
avoid purchasing the propriety hardware that requires cloud access. I am publishing this in hopes other folks are able to expand on this and fill
in any gaps. See capture.gz for a sample capture.

**Everything below this line is AI generated**

**Device:** Kohler RXTLCM combined ATS interface / load control module
**Generator:** Kohler 26 kW residential, RDC2-family controller
**Status:** Partially decoded. Source-availability states are solid; no numeric telemetry exists on this bus.
**Last updated:** 25 July 2026

---

## 1. What this document is

RBUS is Kohler's proprietary accessory bus. It links the RDC2 generator controller to
transfer-switch and load-management accessories. Kohler does not publish it, and no public
decode existed before this work.

This document records what was determined empirically from eight packet captures taken on a
live system, with the generator exercised through known state changes at operator-timestamped
moments. Every claim below is marked with its confidence level and the evidence behind it.

**The short version:** this is a *status* bus, not a *telemetry* bus. It carries booleans —
is utility acceptable, is the generator producing, is the engine running. The numeric values
shown on the RDC2 display (voltage, frequency, battery, engine temperature, runtime hours,
clock) are **not transmitted** and cannot be obtained here. That was established by controlled
experiment, not assumed.

---

## 2. Physical layer

| Property | Value | How established |
|---|---|---|
| Signalling | RS-485 differential, half duplex | Kohler SB-813 documents A/B/PWR/COM on P10 |
| Baud rate | **19200** | Direct measurement: narrowest pulse = 52 µs on a logic analyser |
| Framing | **8 data bits, no parity, 1 stop bit** | Lowest framing-error rate vs 7-bit (22%) and 9-bit (66%) |
| Idle state | High | Line idles high between bursts |
| Poll cycle | ~193 bytes, fixed register order | Autocorrelation peak at 192 bytes, 69.6% self-match |
| Cycle rate | ~4.4 Hz | ~1658 cycles in 348 s |
| Bus load | ~46% of line capacity | Continuous polling even when idle |

**Confidence: HIGH.** The bit period was measured three independent ways — narrowest pulse
width, integer bit-multiples in the run-length histogram (1, 2, 3, 4, 6, 9 bit-times), and
minimum framing errors across candidate framings.

### 2.1 Wiring

The RXT transfer switch board exposes RBUS on **P10** — a four-position pluggable terminal
block with signals labelled **A, B, PWR, COM**. Most boards provide two parallel P10
positions so accessories can be daisy-chained; the spare position is the tap point.

To sniff the bus you need:

- An **isolated RS-485-to-TTL module** (a bare USB-RS485 dongle will not work reliably — see §7)
- Bus side: **A → A, B → B, module isolated GND → COM**. Do **not** connect PWR.
- **Disable the module's 120 Ω terminator.** The bus is already terminated at its ends;
  a third terminator can disrupt communication for the generator itself.
- TTL side: the module's **receiver output** feeds the MCU's UART RX. Leave the module's
  driver input **physically disconnected** so nothing can ever transmit onto the bus.

> **Labelling trap.** On the Waveshare TTL-to-RS485 boards the receiver output is silkscreened
> **TXD**, not RXD — it is labelled from the module's perspective ("data the module transmits
> to the MCU"). Verify with a scope or meter which TTL pin actually toggles before wiring.
> This cost several hours during development.

### 2.2 Safety

Kohler service bulletin **SB-813** exists because people damage these boards making RBUS
connections live. De-energise before connecting: controller to OFF/RESET, E-Stop activated,
upstream utility breaker to the generator opened, starting battery disconnected negative-first,
accessory breaker opened. Restore in reverse. Ground the cable shield at the generator end only.

---

## 3. Encoding — this is the key to reading the protocol

**Two different encodings are used in the same stream.** Missing this is why byte-level
analysis fails; it was the single biggest obstacle in this work.

### 3.1 Literal bytes

Register headers, the utility flag, and the source-state byte are plain wire bytes, compared
directly.

### 3.2 Bit symbols

Elsewhere, the protocol serialises **single bits as multi-byte symbols**:

```
81 01 FF        (3 bytes)  =  bit value 1
BF FF FF FF     (4 bytes)  =  bit value 0
```

This explains three long-standing oddities:

- **0xFF is ~42% of the stream.** It is symbol padding, not data.
- **Frame lengths vary by a byte or two** between otherwise identical frames. The two symbols
  are different lengths, so a frame's byte-size depends on its bit content.
- **Searching for numeric values finds nothing** in these regions. There are no numbers there —
  only bit-fields.

A search for recurring 3- and 4-byte patterns found exactly these two symbols and nothing else;
all other high-frequency patterns are sliding-window overlaps of them.

### 3.3 Bit order

Numeric-looking fields appear **bit-reversed** relative to the wire — the device sends MSB-first
through an LSB-first UART. Confirmed by the register identifier `0x0F`, which reverses to 240
and is constant across every capture. Flags are read from raw wire bytes; only numerics need
reversing.

---

## 4. Register map

One poll cycle contains a fixed sequence of registers, always in the same order. Across eight
captures and every state tested, no register ever appeared conditionally — there are **no
event-driven messages**.

| Anchor bytes | Contents | Decoded? |
|---|---|---|
| `97 2F B7 6F` | 18 bit-symbols (Field 1) + checksum | Partially |
| `97 2D B7 DD` | literal bytes, constant | No |
| `7E BC E8` | **Status register** — utility flag, source state, checksums | **Yes** |
| `97 2F E7 CF` | 6 bit-symbols (Field 2) + checksum | **Yes** |
| `97 2D E7 DD 87` | 1 bit-symbol (Field 3) + checksum | Never asserted |
| `CF 0F FF …` | literal bytes, constant | No |

The leading byte of each header varies between capture sessions (`7D`/`7F`, `BE`/`BF`). This is
a session-level artefact, not state — it does not correlate with any generator condition.
Anchor on the stable portion of each header, not the first byte.

---

## 5. Decoded fields

### 5.1 Status register — anchor `BC E8`

Offsets are relative to the byte following the anchor.

| Offset | Meaning | Values |
|---|---|---|
| 0–1 | Register identifier | always `0F FF` |
| **2–3** | **Utility source** | `FF FF` = present, `01 00` = absent |
| **4** | **Source / output state** | `C7` = on utility<br>`C9` = on utility, alternate form (see §6.1)<br>`FF` = utility lost, not yet producing<br>`5C` or `DC` = generator producing |
| 5, 8, 10 | Checksum / sequence — **not measurements** | 29, 163 and 203 distinct values across 524 samples taken while voltage and frequency were steady |
| 6, 7, 9 | Flags | 3 distinct values each |

**Confidence: HIGH** for offsets 2–4.

*Evidence:* in a capture where the operator opened the ATS utility breaker and later closed it,
offsets 2–3 changed **exactly twice** — at 23.5 s and 289.6 s — matching the two operator
actions. Across the four other captures taken with the ATS on utility, they read `present` in
100% of samples.

### 5.2 Field 1 — anchor `97 2F B7 6F`, 18 bit-symbols

```
000000010101010101   utility present
111111101010101010   transient, immediately after utility loss
110111011010101010   utility absent, settled
```

The trailing alternating pattern appears to be padding or a sync pattern rather than data.
Only the leading bits carry state.

**Confidence: MEDIUM-HIGH.** Transitions align with the utility flag but the field's internal
structure is not fully understood.

### 5.3 Field 2 — anchor `97 2F E7 CF`, 6 bit-symbols

The richest field. Six distinct states observed:

| Bits | Meaning | Samples |
|---|---|---|
| `000110` | On utility, engine stopped | 3,464 |
| `001110` | Engine running, load on utility (exercise / manual / cooldown) | 481 |
| `000010` | Transient during breaker operation | 32 |
| `001010` | Transient during breaker operation | 12 |
| `111001` | Utility lost, engine not producing | 698 |
| `111101` | On generator, engine producing | 568 |

Reading the bits left to right, a coherent assignment emerges:

- **Bit 3** — 1 whenever an acceptable source is available (utility good **or** generator producing)
- **Bit 4** — 1 only while utility is acceptable
- **Bits 0, 1, 2, 5** — move as a block, inverse to utility presence; likely a fault/annunciation group

**Confidence: HIGH** for the state mapping, **MEDIUM** for the individual bit assignments.

> **Width coincidence.** The field is six bits wide and the board carries six load relays.
> A direct relay mapping is **not established** — the bits move in groups rather than
> independently, which is not how six separately-managed loads would behave. This system has
> no load shedding configured (the generator covers the whole panel), so the relays are idle.
> Testable with a meter across the TB2 relay outputs during a transfer.

### 5.4 Field 3 — anchor `97 2D E7 DD 87`, 1 bit-symbol

**Value `0` in every sample of every capture** — approximately 11,600 samples across eight
captures spanning idle, mode changes, manual runs, scheduled exercise, and a full utility
transfer.

A single bit that has never asserted is consistent with a fault or alarm flag that simply has
not been exercised. It could equally be a reserved bit hard-wired to zero. **Unresolved.**

---

## 6. What is NOT on this bus — established by controlled experiment

These were actively searched for and are **absent**:

| Value | How ruled out |
|---|---|
| **Controller mode (AUTO / OFF)** | A capture with two operator-timestamped mode switches (6.99 s and 18.72 s) showed **zero change** anywhere in the stream — identical byte rate (917 vs 918/s), identical status register, and only two byte values differing at 0.05% vs 0.02%, which is noise at those sample sizes |
| **Clock / date** | Two timestamped minute rollovers produced no matching change. Every plausible encoding of the minute value was searched — raw, bit-reversed, BCD, BCD-reversed — with no time-correlated hits |
| **Battery voltage** | Reported 13.1 V in one capture and 13.2 V in another; no byte changed correspondingly. An earlier candidate at offset 6 reads `C1` in both and is constant |
| **Engine temperature** | 116 °F and 98 °F reported in different captures; no correlated byte |
| **Engine runtime hours** | 3.4 h reported; not found in any encoding |
| **Output voltage** | 239–240 V observed while generating; not found as a byte or 16-bit value, either endianness, raw or bit-reversed, in any of the sixteen register anchors |
| **Output frequency** | 59.8–60.2 Hz observed. The values 58/59 appear (bit-reversed) only while generating, which is suggestive, but they do not match and may be a source-quality code rather than a frequency |
| **Slow-updating fields of any kind** | 2,178 consecutive cycles over 10.8 minutes of idle: **107 of 193 byte positions bit-for-bit identical**. Only the status register's checksum and flag bytes moved |

### Why this makes engineering sense

RBUS connects a generator controller to a *transfer switch and load-control module*. Those
devices need to know whether a source is acceptable and when to transfer or shed load. They do
not need to know the engine's oil temperature. The display values stay inside the RDC2.

---

## 7. Open questions

### 7.1 The `C9` status-register variant

The source-state byte takes the value `C9` instead of `C7` in some frames. It is a
**replacement, not an extra message** — exactly 1.00 status registers per cycle either way, at
the identical byte offset (108) within the cycle. Its payload layout differs: offset 5 carries
low values (`01`, `05`, `0F`) where `C7` frames carry high ones (`F7`, `FD`, `FF`).

Observed in exactly two captures — a manual run (8 occurrences) and a forced scheduled exercise
(533 occurrences) — and never in idle-only or transfer captures. In the exercise capture it
appeared from 3.1 s and stopped permanently at 571.6 s.

**Hypothesis (untested):** both captures were sessions where the operator was physically
interacting with the RDC2 control panel, and 571.6 s is close to a typical ten-minute display
timeout. If `C9` is controller-UI traffic rather than generator status it can be ignored
entirely. A capture with deliberate marked button-presses followed by a hands-off period would
confirm or refute this.

### 7.2 Field 3 / fault indication

Would require an actual fault condition to confirm. Not worth manufacturing; capture
opportunistically if one occurs.

### 7.3 Load-shed registers

This installation has no load shedding configured, so those bits — if they exist — sit constant
and are indistinguishable from padding.

### 7.4 The ~86 constant byte positions

Roughly 86 of 193 positions in the poll cycle never changed across any captured state. They
cannot be ruled out as carrying information that only appears in states not yet produced.
This is a limit of the method, not a failure of it: a field that never changes is
indistinguishable from padding.

### 7.5 Checksums

The trailing bytes of each register are almost certainly integrity checks — they change whenever
any payload byte changes. **No standard CRC matched**: CRC-16/CCITT-FALSE, XMODEM, MODBUS, ARC,
KERMIT, MAXIM and USB were all tested against 1,125 unique frames in both endiannesses, plus
8-bit sum and XOR. Either the polynomial is non-standard, or the check covers bytes not visible
at the tap (for example an address byte consumed by the framing).

---

## 8. Capture methodology

For anyone reproducing or extending this work.

**Hardware:** isolated RS-485-to-TTL module + ESP32 DevKit V1 (UART2 RX on the module's
receiver output, driver input left disconnected), USB serial to a laptop.

**Log format** — tab-separated, one record per line:

```
B  <t_us>  <gap_us>  <hex>     one received byte
M  <t_us>  -         <text>    operator marker
#  <t_us>  -         <text>    tool metadata
```

**The single most valuable technique** is the operator marker. Type a note into the serial
console at the moment you act — `breaker open`, `engine started` — and it lands in the log with
a microsecond timestamp. Differential analysis against a known event time is what turns
structure into meaning. Captures without markers are dramatically less useful.

**Experimental design that worked:** change **one variable at a time**, and capture the
transition *within a single log* rather than as two separate steady-state captures. A field
that flips exactly once, exactly when you flipped the breaker, is unmistakable. Two separate
captures of two states can differ for many reasons.

**Traps encountered, in order of time lost:**

1. Reading the receiver output pin by its silkscreen label instead of measuring which pin toggles
2. Probing raw A/B with a logic analyser — its fixed threshold cannot resolve a differential
   pair sitting at 2–3 V common-mode, producing timing that looks correct while the levels are
   corrupt
3. Assuming byte-level encoding throughout, and searching for numeric values in bit-symbol regions
4. Trusting statistical "structure detection" heuristics — several produced confident false
   positives on pure noise. Only direct measurement of the physical layer settled the baud rate

---

## 9. Practical conclusion

What is reliably available from this bus:

- **Utility source present / absent** — hardware-confirmed, at the transfer switch itself
- **Generator producing output** — distinguishes a real transfer from an idle generator
- **Engine running with load on utility** — distinguishes an exercise or cooldown from an outage

That is sufficient to drive an authoritative source-of-supply signal in a home automation
system, and to distinguish a scheduled exercise from a genuine power failure — which
voltage-based inference alone cannot do.

For numeric telemetry (voltage, frequency, battery, runtime), this bus is a dead end. The
remaining options are the RDC2's own service port or Kohler's cloud API, neither of which was
pursued here.
