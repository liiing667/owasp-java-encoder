// Copyright (c) 2026 OWASP
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//     * Redistributions of source code must retain the above
//       copyright notice, this list of conditions and the following
//       disclaimer.
//
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials
//       provided with the distribution.
//
//     * Neither the name of the OWASP nor the names of its
//       contributors may be used to endorse or promote products
//       derived from this software without specific prior written
//       permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// OF THE POSSIBILITY OF SUCH DAMAGE.

package org.owasp.encoder;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.Charset;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

/**
 * Fixed nested-JSON fixtures for {@link Encode#forJsonText(String)}: JSON
 * text that is embedded again as a string value of an outer JSON document,
 * as a page does when it re-embeds serialized output.  The fixtures show
 * that legal JSON text round-trips to itself through the encoding, the
 * HTML script embedding context and both JSON decodes, and that illegal
 * control characters and unpaired surrogates are rejected before any
 * output is produced.
 */
public class JSONTextEmbeddingTest extends TestCase {
    private static final Charset UTF_8 = Charset.forName("UTF-8");

    /**
     * Legal JSON texts, most of them nested: their string values contain
     * JSON text themselves.  Backslashes, quotes and the Unicode line
     * separators U+2028 and U+2029 appear at every nesting level.
     */
    private static final String[] NESTED_JSON_TEXTS = {
        // An object whose string value is itself a JSON document.
        "{\"config\":\"{\\\"theme\\\":\\\"daybreak-blue\\\",\\\"flags\\\":[true,false]}\"}",
        // Three levels: a JSON string of a JSON object of a JSON string.
        "\"{\\\"l2\\\":\\\"{\\\\\\\"l3\\\\\\\":\\\\\\\"v\\\\\\\"}\\\"}\"",
        // Backslashes and quotes inside the nested document.
        "{\"path\":\"C:\\\\temp\\\\\",\"q\":\"a\\\"b\",\"re\":\"\\\\d+\"}",
        // Raw U+2028 and U+2029 are legal in JSON text.
        "{\"lines\":\"a\u2028b\u2029c\"}",
        // HTML script delimiters inside the nested document.
        "{\"html\":\"</script><script>alert(1)</script>\",\"markup\":\"<b>&amp;</b>\"}",
        // Non-ASCII and a surrogate pair.
        "{\"label\":\"caf\u00e9 \u2615\",\"emoji\":\"\ud83d\ude00\"}",
        // An array mixing scalars and nested JSON text.
        "[1,\"[2,3]\",{\"a\":\"{\\\"b\\\":null}\"}]",
        // Scalar JSON texts.
        "null",
        "true",
        "42",
        "\"plain\"",
    };

    private final ObjectMapper _mapper = new ObjectMapper();

    public static Test suite() {
        return new TestSuite(JSONTextEmbeddingTest.class);
    }

    /**
     * The fixtures are legal JSON text: an independent parser accepts each
     * of them from UTF-8 bytes.
     */
    public void testFixturesAreLegalJsonText() throws IOException {
        for (String text : NESTED_JSON_TEXTS) {
            _mapper.readTree(text.getBytes(UTF_8));
        }
    }

    /**
     * Round trip: the encoded text, wrapped in the caller's quotes and
     * exchanged as UTF-8, parses back to the identical JSON text.  Legal
     * JSON text is preserved.
     */
    public void testNestedJsonTextRoundTripsThroughUtf8() throws IOException {
        for (String text : NESTED_JSON_TEXTS) {
            String encoded = Encode.forJsonText(text);
            String parsed = _mapper.readValue(
                ("\"" + encoded + "\"").getBytes(UTF_8), String.class);
            assertEquals(EncoderTestSuiteBuilder.debugEncode(text),
                EncoderTestSuiteBuilder.debugEncode(text),
                EncoderTestSuiteBuilder.debugEncode(parsed));
        }
    }

    /**
     * One identity: for legal JSON text the fail-closed facade produces
     * exactly the JSON string encoding, so the encoding, the embedding
     * context and the round trip are the same contract.
     */
    public void testLegalTextUsesTheJsonStringEncoding() {
        for (String text : NESTED_JSON_TEXTS) {
            assertEquals(Encode.forJson(text), Encode.forJsonText(text));
        }
    }

    /**
     * The encoded nested text never contains a character that could end
     * the HTML script element or a pre-ES2019 JavaScript line, and only
     * uses the escapes RFC 8259 defines.
     */
    public void testEncodedOutputStaysInsideTheEmbeddingContext() {
        for (String text : NESTED_JSON_TEXTS) {
            String encoded = Encode.forJsonText(text);
            String context = EncoderTestSuiteBuilder.debugEncode(text);
            for (int i = 0, n = encoded.length(); i < n; ++i) {
                char ch = encoded.charAt(i);
                if (ch == '\\') {
                    assertTrue(context + ": dangling backslash", i + 1 < n);
                    char esc = encoded.charAt(++i);
                    if (esc == 'u') {
                        assertTrue(context, i + 4 < n);
                        i += 4;
                    } else {
                        assertTrue(context + ": unexpected escape \\" + esc,
                            "\"\\btnfr".indexOf(esc) >= 0);
                    }
                } else {
                    assertFalse(context + ": raw character leaves the context",
                        ch < ' ' || ch == '<' || ch == '>' || ch == '&'
                        || ch == '\u2028' || ch == '\u2029');
                }
            }
        }
    }

    /**
     * The page scenario: the encoded text is embedded as a nested string
     * of an outer JSON document inside an HTML script element.  The HTML
     * parser sees one script, the outer JSON decode returns the identical
     * JSON text, and the inner decode equals parsing the text directly.
     */
    public void testNestedEmbeddingInScriptElementRoundTrips() throws IOException {
        for (String text : NESTED_JSON_TEXTS) {
            String outer = "{\"payload\":\"" + Encode.forJsonText(text) + "\"}";
            String page = "<script type=\"application/json\" id=\"data\">"
                + outer + "</script><p id=after>after</p>";

            Document document = Jsoup.parse(page);
            assertEquals(text, 1, document.select("script").size());
            assertEquals(text, "after", document.getElementById("after").text());
            String content = document.getElementById("data").data();
            assertEquals(text, outer, content);

            String payload = _mapper.readTree(content.getBytes(UTF_8))
                .get("payload").asText();
            assertEquals(text, payload);
            assertEquals(_mapper.readTree(text.getBytes(UTF_8)),
                _mapper.readTree(payload.getBytes(UTF_8)));
        }
    }

    /**
     * Fail closed: a raw control character anywhere in the JSON text is
     * rejected before any output is produced, whether it appears inside a
     * string, after a document, or before one.
     */
    public void testRawControlCharactersAreRejected() throws IOException {
        for (char ch = 0; ch < ' '; ++ch) {
            String[] texts = {
                "{\"a\":\"x" + ch + "y\"}",
                "{\"a\":1}" + ch,
                ch + "{\"a\":1}",
            };
            for (String text : texts) {
                assertRejected(text, ch);
            }
        }
    }

    /**
     * Fail closed: an unpaired surrogate has no UTF-8 representation, so
     * it cannot round-trip and is rejected before any output.
     */
    public void testUnpairedSurrogatesAreRejected() throws IOException {
        String[] texts = {
            "{\"a\":\"\ud800\"}",
            "{\"a\":\"\udc00\"}",
            "{\"a\":\"x\"}\ud800",
            "\udc00{\"a\":1}",
        };
        for (String text : texts) {
            assertRejected(text, -1);
        }
    }

    /**
     * Shows why the facade is fail-closed: nested JSON text with a raw
     * control character cannot survive the second decode, so accepting it
     * would break the identity between encoding and reversibility.
     */
    public void testRawControlCharacterBreaksTheSecondDecode() throws IOException {
        String text = "{\"a\":\"x\ty\"}";
        try {
            _mapper.readTree(text.getBytes(UTF_8));
            fail("raw tab inside JSON text must not parse");
        } catch (IOException expected) {
            // RFC 8259 requires control characters to be escaped.
        }
    }

    /**
     * The boundary between the two JSON facades: {@code forJson} escapes
     * control characters in arbitrary string content, while
     * {@code forJsonText} rejects them in JSON text.
     */
    public void testForJsonStillEscapesWhatForJsonTextRejects() {
        assertEquals("\\t", Encode.forJson("\t"));
        try {
            Encode.forJsonText("\t");
            fail("forJsonText must reject a raw control character");
        } catch (IllegalArgumentException expected) {
            // Fail-closed JSON text policy.
        }
    }

    /**
     * Null follows the facade convention and encodes as the text
     * {@code null}; empty input contains no illegal characters.
     */
    public void testNullAndEmptyInput() {
        assertEquals("null", Encode.forJsonText(null));
        assertEquals("", Encode.forJsonText(""));
    }

    /**
     * The streaming context cannot validate up front, so the registered
     * encoder retains the escape-everything behavior; only the facade is
     * fail-closed.
     */
    public void testStreamingContextRetainsEscapingBehavior() throws IOException {
        StringWriter out = new StringWriter();
        EncodedWriter writer = new EncodedWriter(out, Encoders.JSON_TEXT);
        writer.write("\t");
        writer.close();
        assertEquals("\\t", out.toString());
    }

    /**
     * Asserts both facade overloads reject the text with an
     * {@link IllegalArgumentException} and the Writer receives nothing.
     *
     * @param text the illegal JSON text
     * @param ch the offending control character, or -1 for a surrogate
     */
    private static void assertRejected(String text, int ch) throws IOException {
        String label = ch < 0 ? "unpaired surrogate"
            : String.format("control 0x%02X", ch);
        try {
            Encode.forJsonText(text);
            fail("forJsonText must reject " + label + " in "
                + EncoderTestSuiteBuilder.debugEncode(text));
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage(),
                expected.getMessage().startsWith("JSON text contains"));
        }
        StringWriter out = new StringWriter();
        try {
            Encode.forJsonText(out, text);
            fail("forJsonText(Writer) must reject " + label);
        } catch (IllegalArgumentException expected) {
            // Fail closed before any output.
        }
        assertEquals("Writer emits nothing on rejection", "", out.toString());
    }
}
