#!/usr/bin/env python3
"""
rbus_decode.py — Kohler RBUS decoder for the RXTLCM (RXT ATS + LCM board)

Scope
    Decodes every field confirmed against observed generator behaviour.
    Each field below was validated against captures in which the operator
    performed a known action at a known time, or reported a displayed
    value at a known time.

PHYSICAL LAYER  (settled by direct measurement, not inference)
    19200 baud, 8 data bits, no parity, 1 stop bit.
    Confirmed three ways: narrowest pulse width measured at 52 us on a
    logic analyser, integer bit-multiples in the run-length histogram,
    and the lowest framing-error rate against 7-bit and 9-bit framing.

TWO ENCODINGS ARE IN USE — this is the key to reading the protocol

  1. LITERAL BYTES
     Register headers, the utility flag, and the source/output state are
     plain wire bytes, compared directly.

  2. BIT SYMBOLS
     Elsewhere the protocol serialises single bits as multi-byte symbols:

         81 01 FF        (3 bytes)  =  bit 1
         BF FF FF FF     (4 bytes)  =  bit 0

     This is why byte-value analysis of those regions finds nothing: the
     regions hold bit-fields, not numbers.  It also explains the two
     long-standing oddities in this protocol — that 0xFF is ~42% of the
     stream (symbol padding), and that frame lengths vary by a byte or
     two between otherwise identical frames (the two symbols are
     different lengths, so a frame's size depends on its bit content).

BIT ORDER
    Numeric-looking fields appear bit-reversed relative to the wire, i.e.
    the device sends MSB-first through an LSB-first UART.  Evidence:
    wire 0x0F reverses to 240 as a stable register identifier.  Flags are
    read from raw wire bytes; reverse_bits() is provided for numerics.

DECODED FIELDS

  STATUS REGISTER   anchor BC E8, literal bytes
      offset 0-1    0x0F 0xFF   constant register identifier
      offset 2-3    UTILITY SOURCE          FF FF = present
                                            01 00 = absent
      offset 4      SOURCE / OUTPUT STATE   C7       = on utility
                                            FF       = utility lost,
                                                       not yet producing
                                            5C or DC = generator producing
      offset 5,8,10 HIGH-VARIABILITY bytes — checksum or sequence, NOT
                    measurements.  Across 524 consecutive samples taken
                    while the operator observed a steady 239-240 V and
                    59.8-60.2 Hz, these offsets took 29, 163 and 203
                    distinct values respectively.  A stable reading would
                    take one to three.  They change essentially every
                    frame regardless of content.
      offset 6,9    3 distinct values each (C1, BF, C3) — flags.
      offset 7      3 distinct values (72, 5C, DC) — flag.

    NOTE: an earlier reading of offsets 5-10 as two symmetric per-leg
    measurement groups was WRONG.  The symmetry is flag/checksum/flag,
    not prefix/measurement/suffix.  There are no numeric measurements
    anywhere in this protocol; every decodable field is boolean state.

  FIELD 1   anchor 97 2F B7 6F, 18 bit symbols
      000000010101010101   utility present
      111111101010101010   transient immediately after utility loss
      110111011010101010   utility absent, settled

  FIELD 2   anchor 97 2F E7 CF, 6 bit symbols — the richest field
      000110   normal, on utility
      000010   transient during breaker operation
      001010   transient during breaker operation
      111001   utility lost, generator not producing
      111101   generator producing
      Bit 3 is 1 whenever an acceptable source is available (utility good
      or generator producing).  Bit 4 is 1 only while utility is good.
      Bits 0,1,2,5 move as a block, inverse to utility presence.
      The width matches the six load relays on the board, but the bits
      move in groups rather than independently, so a direct relay mapping
      is NOT established.

  FIELD 3   anchor 97 2D E7 DD 87, 1 bit symbol
      0 in every capture and every state recorded so far.  A single bit
      that has never asserted is consistent with a fault or alarm flag
      that has simply never been exercised.  Unconfirmed.

NOT PRESENT ON THIS BUS — established by controlled experiment
    Controller mode (AUTO/OFF), clock/date, engine temperature, battery
    voltage, and engine runtime hours are NOT transmitted to this
    accessory.  A capture spanning two operator-timestamped mode switches
    and two clock rollovers showed no change anywhere in the stream:
    identical byte rate, identical status register, and no encoding of
    the minute value (raw, reversed, BCD, BCD-reversed) with a matching
    time distribution.  Output voltage was likewise not found in any
    register in any encoding tried.

    RBUS carries what a transfer switch and load-control module need:
    source availability and load management.  The remaining display
    values stay inside the RDC2 controller.

Usage
    python3 rbus_decode.py capture.log            summary per capture
    python3 rbus_decode.py --timeline capture.log  timestamped changes
    python3 rbus_decode.py --verify capture.log    full evidence dump

Conventions
    Stdlib only.  Read-only.  Reports the confidence of each field rather
    than presenting unvalidated inferences as results.
"""

import argparse
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

STATUS_ANCHOR = (0xBC, 0xE8)

OFFSET_UTILITY_HIGH = 2
OFFSET_UTILITY_LOW = 3
OFFSET_SOURCE_STATE = 4
OFFSET_PAYLOAD = 5
STATUS_WINDOW = 11

UTILITY_PRESENT = (0xFF, 0xFF)
UTILITY_ABSENT = (0x01, 0x00)

SOURCE_ON_UTILITY = 0xC7
SOURCE_ON_UTILITY_ALT = 0xC9
SOURCE_UTILITY_LOST = 0xFF
SOURCE_GENERATING = (0x5C, 0xDC)

# Bit symbols.  See the module docstring for how these were identified.
SYMBOL_ONE = (0x81, 0x01, 0xFF)
SYMBOL_ZERO = (0xBF, 0xFF, 0xFF, 0xFF)

# Anchors introducing bit-symbol fields, with the field name.
BIT_FIELDS = [
    ((0x97, 0x2F, 0xB7, 0x6F), "field1", 18),
    ((0x97, 0x2F, 0xE7, 0xCF), "field2", 6),
    ((0x97, 0x2D, 0xE7, 0xDD, 0x87), "field3", 1),
]

# Interpretations validated against the operator-timestamped transfer test.
FIELD1_MEANINGS = {
    "000000010101010101": "utility present",
    "111111101010101010": "utility just lost (transient)",
    "110111011010101010": "utility absent",
}

FIELD2_MEANINGS = {
    "000110": "on utility, engine stopped",
    "000010": "transient (breaker operation)",
    "001010": "transient (breaker operation)",
    "001110": "engine running, load on utility (exercise/manual/cooldown)",
    "111001": "utility lost, engine not producing",
    "111101": "on generator, engine producing",
}

# A state is reported only after this many agreeing samples, so a single
# corrupted poll cannot flip the output.
HYSTERESIS_SAMPLES = 3


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def reverse_bits(value: int) -> int:
    """Return the bit-reversed byte, undoing the MSB/LSB-first mismatch."""
    return int(f"{value:08b}"[::-1], 2)


def read_capture(path: str):
    """Return ([times_us], [bytes], [(time_us, marker_text)])."""
    times, values, markers = [], [], []
    with open(path, encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 4:
                continue
            try:
                if parts[0] == "B":
                    times.append(int(parts[1]))
                    values.append(int(parts[3], 16))
                elif parts[0] == "M":
                    markers.append((int(parts[1]), parts[3]))
            except ValueError:
                continue
    return times, values, markers


def find_anchor(values, anchor):
    """Yield each index just past an occurrence of the anchor sequence."""
    length = len(anchor)
    limit = len(values) - length
    first = anchor[0]
    for index in range(limit):
        if values[index] != first:
            continue
        if tuple(values[index:index + length]) == anchor:
            yield index + length


# ---------------------------------------------------------------------------
# Field decoders
# ---------------------------------------------------------------------------

def decode_utility(register) -> str:
    """Utility source presence, from raw wire bytes.  HIGH confidence."""
    pair = (register[OFFSET_UTILITY_HIGH], register[OFFSET_UTILITY_LOW])
    if pair == UTILITY_PRESENT:
        return "present"
    if pair == UTILITY_ABSENT:
        return "absent"
    return "unknown"


def decode_source_state(register) -> str:
    """Generator output state, from raw wire bytes.  HIGH confidence.

    C9 is a second form of the on-utility register.  It replaces C7 in the
    same cycle slot rather than adding a message, and carries a different
    payload layout (offset 5 holds low values where C7 holds high ones).
    Observed only in captures where the engine ran, and it ceases
    permanently partway through such a capture.  Its meaning is NOT
    established, so it is reported distinctly rather than merged with C7.
    """
    value = register[OFFSET_SOURCE_STATE]
    if value == SOURCE_ON_UTILITY:
        return "on-utility"
    if value == SOURCE_ON_UTILITY_ALT:
        return "on-utility-alt"
    if value in SOURCE_GENERATING:
        return "generating"
    if value == SOURCE_UTILITY_LOST:
        return "not-generating"
    return "unknown"


def decode_bit_symbols(values, start, limit=40):
    """Read consecutive bit symbols from `start`.  Returns a bit string."""
    bits = []
    index = start
    end = min(len(values), start + limit * 4)
    while index < end:
        if tuple(values[index:index + 3]) == SYMBOL_ONE:
            bits.append("1")
            index += 3
        elif tuple(values[index:index + 4]) == SYMBOL_ZERO:
            bits.append("0")
            index += 4
        else:
            break
    return "".join(bits)


def collect_status_registers(times, values):
    """Return [(time_us, [bytes])] for each status register occurrence."""
    out = []
    for start in find_anchor(values, STATUS_ANCHOR):
        if start + STATUS_WINDOW <= len(values):
            out.append((times[start], values[start:start + STATUS_WINDOW]))
    return out


def collect_bit_field(times, values, anchor, expected_width):
    """Return [(time_us, bitstring)] for one bit-symbol field."""
    out = []
    for start in find_anchor(values, anchor):
        bits = decode_bit_symbols(values, start)
        if bits:
            out.append((times[start], bits))
    return out


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def summarise(path: str) -> None:
    times, values, markers = read_capture(path)
    registers = collect_status_registers(times, values)

    print(f"\n{'=' * 74}")
    print(f"FILE      {path}")
    print(f"BYTES     {len(values)}")
    if times:
        # A backward step in the timestamp means the ESP32 restarted, which
        # resets micros() to zero.  Report the resets rather than inventing
        # an elapsed time across the discontinuity.
        resets = sum(1 for a, b in zip(times, times[1:]) if b < a)
        if resets:
            print(f"DURATION  unreliable — {resets} capture restart(s) "
                  f"in this log")
        else:
            print(f"DURATION  {(times[-1] - times[0]) / 1e6:.1f} s")

    if markers:
        print("MARKERS")
        origin = times[0] if times else 0
        for stamp, text in markers:
            print(f"            {(stamp - origin) / 1e6:8.2f}s  {text}")

    if not registers:
        print("STATUS    no status registers found")
        return

    utility = Counter(decode_utility(r) for _, r in registers)
    source = Counter(decode_source_state(r) for _, r in registers)
    print(f"SAMPLES   {len(registers)} status registers")
    print(f"UTILITY   {dict(utility)}")
    print(f"SOURCE    {dict(source)}")

    for anchor, name, width in BIT_FIELDS:
        field = collect_bit_field(times, values, anchor, width)
        if not field:
            continue
        counts = Counter(bits for _, bits in field)
        print(f"{name.upper():9s} {len(field)} samples")
        for bits, count in counts.most_common(6):
            if name == "field1":
                meaning = FIELD1_MEANINGS.get(bits, "unrecognised")
            elif name == "field2":
                meaning = FIELD2_MEANINGS.get(bits, "unrecognised")
            else:
                meaning = "never asserted" if set(bits) == {"0"} else "ASSERTED"
            print(f"            {bits:20s} x{count:<6d} {meaning}")


def timeline(path: str) -> None:
    """Print every state change with a timestamp, applying hysteresis."""
    times, values, markers = read_capture(path)
    registers = collect_status_registers(times, values)
    if not registers:
        print(f"{path}: no status registers found")
        return

    origin = registers[0][0]
    events = []

    for stamp, text in markers:
        events.append(((stamp - origin) / 1e6, "MARKER", text))

    def scan(samples, decoder, label):
        reported, pending, run = None, None, 0
        for stamp, item in samples:
            current = decoder(item)
            if current == pending:
                run += 1
            else:
                pending, run = current, 1
            if run >= HYSTERESIS_SAMPLES and current != reported:
                if reported is not None:
                    events.append(((stamp - origin) / 1e6, label,
                                   f"{reported} -> {current}"))
                else:
                    events.append(((stamp - origin) / 1e6, label,
                                   f"initial {current}"))
                reported = current

    scan(registers, decode_utility, "utility")
    scan(registers, decode_source_state, "source")

    for anchor, name, width in BIT_FIELDS:
        field = collect_bit_field(times, values, anchor, width)
        if field:
            scan(field, lambda bits: bits, name)

    events.sort(key=lambda item: item[0])
    print(f"\n{'=' * 74}")
    print(f"FILE      {path}")
    print(f"TIMELINE  {len(registers)} status samples\n")
    for seconds, label, detail in events:
        print(f"  {seconds:9.2f}s  {label:8s}  {detail}")


def verify(path: str) -> None:
    """Dump the raw evidence behind each decoded field."""
    times, values, markers = read_capture(path)
    registers = collect_status_registers(times, values)

    print(f"\n{'=' * 74}")
    print(f"EVIDENCE  {path}")
    if not registers:
        print("  no status registers found")
        return

    print(f"\n  Status register raw bytes, grouped by decoded state:")
    grouped = {}
    for _, register in registers:
        key = (decode_utility(register), decode_source_state(register))
        grouped.setdefault(key, Counter())[tuple(register)] += 1

    for (utility, source), contents in sorted(grouped.items()):
        total = sum(contents.values())
        print(f"\n    utility={utility:8s} source={source:15s} n={total}")
        for register, count in contents.most_common(3):
            hexed = " ".join(f"{b:02X}" for b in register)
            print(f"        {hexed}   x{count}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decode the Kohler RBUS RXTLCM protocol")
    parser.add_argument("logs", nargs="+", help="capture log files")
    parser.add_argument("--timeline", action="store_true",
                        help="print timestamped state changes")
    parser.add_argument("--verify", action="store_true",
                        help="dump raw bytes behind each decoded state")
    args = parser.parse_args()

    for path in args.logs:
        try:
            if args.timeline:
                timeline(path)
            elif args.verify:
                verify(path)
            else:
                summarise(path)
        except OSError as exc:
            print(f"Cannot read {path}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
