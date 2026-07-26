/*
 * rbus_uart_probe.ino — ESP32 UART receive path validation and RBUS capture
 *
 * Purpose
 *     Proves the ESP32 UART receive path at 19200 8N1 before the isolated
 *     RS-485 module arrives, then becomes the capture firmware unchanged.
 *
 * Two modes, selected by MODE_LOOPBACK below:
 *
 *     MODE_LOOPBACK = 1   Self-test.  Transmits a known pattern on TX and
 *                         verifies it arrives on RX.  Jumper TX to RX.
 *                         Reports byte errors and timing.
 *
 *     MODE_LOOPBACK = 0   Capture.  Receive only.  Emits timestamped bytes
 *                         over USB serial in the same tab-separated format
 *                         as rbus_capture2.py, so the existing analysis
 *                         tooling works without modification.
 *
 * Wiring (capture mode, once the isolated module arrives)
 *     Module RXD/RO  -> ESP32 GPIO16 (UART2 RX)
 *     Module TXD/DI  -> leave DISCONNECTED (hardware guarantee: the ESP32
 *                       can never transmit onto the Kohler bus)
 *     Module RE/DE   -> tie for permanent receive, if the module has it
 *     Module VCC/GND -> ESP32 3V3 and GND (TTL side only)
 *     Module A/B/GND -> Kohler A, B, and COM (bus side, isolated)
 *
 * Safety
 *     UART2 TX is never initialised in capture mode.  Do not connect the
 *     module's DI pin.  Disable the module's 120R terminator: the RBUS
 *     already has termination at its ends.
 *
 * Conventions
 *     Arduino core for ESP32.  No hardcoded network config; this sketch
 *     only does serial.  Network reporting is a separate concern and will
 *     live in the SMAH bridge firmware once the protocol is decoded.
 */

#include <Arduino.h>

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#define MODE_LOOPBACK 1        // 1 = self-test, 0 = capture from bus

static const uint32_t BUS_BAUD    = 19200;
static const int      PIN_BUS_RX  = 16;   // UART2 RX
static const int      PIN_BUS_TX  = 17;   // UART2 TX (loopback test only)

static const uint32_t USB_BAUD    = 921600;  // fast, so logging is not the
                                             // bottleneck during bursts

// A gap at least this long is reported as an inter-frame boundary, matching
// the analysis assumptions in rbus_score2.py.  Measured RBUS poll gaps sit
// around 50 ms with 1-4 ms intra-burst activity.
static const uint32_t FRAME_GAP_US = 2000;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

static uint32_t g_startMicros    = 0;
static uint32_t g_lastByteMicros = 0;
static uint32_t g_byteCount      = 0;

// ---------------------------------------------------------------------------
// Loopback self-test
// ---------------------------------------------------------------------------

#if MODE_LOOPBACK

// Pattern chosen to exercise every bit position and several run lengths,
// including values seen in the real captures.
static const uint8_t kPattern[] = {
    0x00, 0xFF, 0x55, 0xAA, 0x0F, 0xF0, 0x01, 0x80,
    0xEF, 0xFB, 0xBF, 0x81, 0x7E, 0xE7, 0x3C, 0xC3
};
static const size_t kPatternLength = sizeof(kPattern);

static void runLoopbackTest()
{
    Serial.println(F("# loopback: jumper GPIO17 (TX) to GPIO16 (RX)"));
    Serial.printf("# sending %u bytes at %u baud\n",
                  (unsigned)kPatternLength, (unsigned)BUS_BAUD);

    // Flush anything stale before measuring.
    while (Serial2.available()) {
        Serial2.read();
    }

    const uint32_t sentAt = micros();
    Serial2.write(kPattern, kPatternLength);
    Serial2.flush();

    uint8_t received[kPatternLength];
    size_t  count   = 0;
    const uint32_t deadline = millis() + 500;

    while (count < kPatternLength && millis() < deadline) {
        if (Serial2.available()) {
            received[count++] = (uint8_t)Serial2.read();
        }
    }

    const uint32_t elapsed = micros() - sentAt;

    Serial.printf("# received %u of %u bytes in %u us\n",
                  (unsigned)count, (unsigned)kPatternLength,
                  (unsigned)elapsed);

    if (count != kPatternLength) {
        Serial.println(F("# FAIL: byte count mismatch"));
        Serial.println(F("#   check the TX-RX jumper and pin assignment"));
        return;
    }

    size_t mismatches = 0;
    for (size_t i = 0; i < kPatternLength; ++i) {
        if (received[i] != kPattern[i]) {
            ++mismatches;
            Serial.printf("#   byte %u: sent %02X received %02X\n",
                          (unsigned)i, kPattern[i], received[i]);
        }
    }

    if (mismatches == 0) {
        // 10 bit-times per byte at 8N1.
        const uint32_t expected =
            (uint32_t)((1000000.0 * 10.0 * kPatternLength) / BUS_BAUD);
        Serial.println(F("# PASS: all bytes matched"));
        Serial.printf("# expected ~%u us, measured %u us\n",
                      (unsigned)expected, (unsigned)elapsed);
        Serial.println(F("# UART path is proven at 19200 8N1."));
        Serial.println(F("# Set MODE_LOOPBACK to 0 for capture."));
    } else {
        Serial.printf("# FAIL: %u mismatched bytes\n", (unsigned)mismatches);
        Serial.println(F("#   a few mismatches suggest a baud or clock issue"));
        Serial.println(F("#   many mismatches suggest wrong pins or wiring"));
    }
}

#endif  // MODE_LOOPBACK

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

static void emitByte(uint8_t value, uint32_t nowMicros)
{
    const uint32_t relative = nowMicros - g_startMicros;
    const uint32_t gap      = nowMicros - g_lastByteMicros;

    // Tab-separated, matching rbus_capture2.py so existing analysis tools
    // read this output unchanged.
    Serial.printf("B\t%u\t%u\t%02X\n",
                  (unsigned)relative,
                  (unsigned)(gap >= FRAME_GAP_US ? gap : 0),
                  value);

    g_lastByteMicros = nowMicros;
    ++g_byteCount;
}

// Operator markers.  Anything typed into the USB serial console during a
// capture is emitted as a timestamped M record, in the same format the
// analysis tools already expect.  This is how transitions get annotated:
// type "breaker open" and press Enter at the moment you flip it.
//
// Any serial terminal that can send a line works — the Arduino IDE monitor,
// cutecom, screen, or minicom.  In cutecom, type into the input box and
// press Enter; set line ending to LF or CR, both are handled.
static void pollMarkers()
{
    static char    buffer[64];
    static uint8_t length = 0;

    while (Serial.available()) {
        const char character = (char)Serial.read();

        if (character == '\n' || character == '\r') {
            if (length > 0) {
                buffer[length] = '\0';
                Serial.printf("M\t%u\t-\t%s\n",
                              (unsigned)(micros() - g_startMicros),
                              buffer);
                length = 0;
            }
            continue;
        }

        if (length < sizeof(buffer) - 1) {
            buffer[length++] = character;
        }
    }
}

static void runCapture()
{
    while (Serial2.available()) {
        const uint8_t value = (uint8_t)Serial2.read();
        emitByte(value, micros());
    }

    pollMarkers();

    // Periodic heartbeat so a silent bus is distinguishable from a hung
    // sketch.  Deliberately infrequent to avoid polluting the byte stream.
    static uint32_t lastReport = 0;
    const uint32_t now = millis();
    if (now - lastReport >= 10000) {
        lastReport = now;
        Serial.printf("#\t%u\t-\tbytes=%u\n",
                      (unsigned)(micros() - g_startMicros),
                      (unsigned)g_byteCount);
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

void setup()
{
    Serial.begin(USB_BAUD);
    delay(200);

#if MODE_LOOPBACK
    // Loopback needs both directions.
    Serial2.begin(BUS_BAUD, SERIAL_8N1, PIN_BUS_RX, PIN_BUS_TX);
#else
    // Capture is receive-only: pass -1 as the TX pin so the ESP32 never
    // drives a transmit line at all.
    Serial2.begin(BUS_BAUD, SERIAL_8N1, PIN_BUS_RX, -1);
#endif

    // A larger driver buffer tolerates USB write stalls during bursts.
    Serial2.setRxBufferSize(2048);

    g_startMicros    = micros();
    g_lastByteMicros = g_startMicros;

    Serial.println(F("#\t0\t-\ttool=rbus_uart_probe"));
    Serial.printf("#\t0\t-\tbaud=%u mode=%s\n",
                  (unsigned)BUS_BAUD,
#if MODE_LOOPBACK
                  "loopback"
#else
                  "capture"
#endif
    );

#if MODE_LOOPBACK
    delay(500);
    runLoopbackTest();
#endif
}

void loop()
{
#if MODE_LOOPBACK
    delay(1000);   // test runs once in setup
#else
    runCapture();
#endif
}
