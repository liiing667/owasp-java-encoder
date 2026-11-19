// Copyright (c) 2012 Jeff Ichnowski
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

import java.io.StringWriter;
import java.nio.CharBuffer;
import java.nio.charset.CoderResult;
import java.util.Arrays;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import junit.framework.Test;
import junit.framework.TestCase;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

/**
 * CDATAEncoderTest -- Test the CDATAEncoder for all code-points.
 *
 * @author Jeff Ichnowski
 */
public class CDATAEncoderTest extends TestCase {

    /** A parsed-value-preserving spelling of {@code "]"}. */
    private static final String RB = "]]>]<![CDATA[";

    /** A value-preserving spelling of {@code ">"}. */
    private static final String GT = "]]><![CDATA[>";

    public static Test suite() {
        // The builder's safe/unsafe affix composition builds inputs that
        // contain a literal "]]>" once encoded brackets are involved, which
        // the fail-closed encoder correctly rejects; bracket spellings are
        // therefore asserted in dedicated test methods below. The suite here
        // classifies every code point as valid, encoded, or rejected.
        return new EncoderTestSuiteBuilder(CDATAEncoderTest.class, new CDATAEncoder(), "-safe-", "-x-")
            // Every code point is classified exactly once: encoded, valid and
            // passed through, or invalid and rejected by the fail-closed
            // encoder.
            .invalid(0x00, 0x08)
            .valid("\t\r\n")
            .invalid(0x0b, 0x0c)
            .invalid(0x0e, 0x1f)
            .valid(' ', Character.MAX_CODE_POINT)
            .encoded("]>")
            .invalid(0x80, 0x84)
            .invalid(0x86, 0x9f)
            .invalid(Character.MIN_SURROGATE, Character.MAX_SURROGATE)
            .invalid(0xfdd0, 0xfdef)
            .invalid(0xfffe, 0xffff)
            .invalid(0x1fffe, 0x1ffff)
            .invalid(0x2fffe, 0x2ffff)
            .invalid(0x3fffe, 0x3ffff)
            .invalid(0x4fffe, 0x4ffff)
            .invalid(0x5fffe, 0x5ffff)
            .invalid(0x6fffe, 0x6ffff)
            .invalid(0x7fffe, 0x7ffff)
            .invalid(0x8fffe, 0x8ffff)
            .invalid(0x9fffe, 0x9ffff)
            .invalid(0xafffe, 0xaffff)
            .invalid(0xbfffe, 0xbffff)
            .invalid(0xcfffe, 0xcffff)
            .invalid(0xdfffe, 0xdffff)
            .invalid(0xefffe, 0xeffff)
            .invalid(0xffffe, 0xfffff)
            .invalid(0x10fffe, 0x10ffff)
            .validSuite()
            .rejectSuite()
            .build();
    }

    public void testMaxEncodedLength() {
        CDATAEncoder encoder = new CDATAEncoder();
        assertEquals(0, encoder.maxEncodedLength(0));
        assertEquals(13, encoder.maxEncodedLength(1));
        assertEquals(26, encoder.maxEncodedLength(2));
        assertEquals(39, encoder.maxEncodedLength(3));
        assertEquals(52, encoder.maxEncodedLength(4));
        assertEquals(65, encoder.maxEncodedLength(5));
        assertEquals(78, encoder.maxEncodedLength(6));
        assertEquals(Integer.MAX_VALUE,
            encoder.maxEncodedLength(Integer.MAX_VALUE / 13 + 1));
    }

    public void testBracketAndAngleSpellingsPreserveParsedValue()
            throws Exception {
        Object[][] cases = {
            {"]", RB}, {"]]", RB + RB}, {"]]]]]", RB + RB + RB + RB + RB},
            {">", GT}, {">>", GT + GT}, {"]>", RB + GT}, {">]", GT + RB},
            {"<\"&'>", "<\"&'" + GT},
        };
        DocumentBuilder parser = newParser();
        for (Object[] fixture : cases) {
            String input = (String) fixture[0];
            String expected = (String) fixture[1];
            assertEquals("encoding of " + debug(input), expected,
                Encode.forCDATA(input));
            assertParsedValue(parser, input, expected);
        }
    }

    public void testStringFacadeDoesNotEagerlyAllocateMaximumExpansion() {
        CDATAEncoder encoder = new CDATAEncoder() {
            @Override
            protected int maxEncodedLength(int n) {
                throw new AssertionError("String facade must grow from actual output");
            }
        };
        String input = "]" + repeat('a', Encode.Buffer.INPUT_BUFFER_SIZE * 4);
        assertEquals(Encode.forCDATA(input), Encode.encode(encoder, input));
    }

    public void testHighExpansionRunUsesDocumentedBound() throws Exception {
        char[] chars = new char[100000];
        Arrays.fill(chars, ']');
        String input = new String(chars);
        String encoded = Encode.forCDATA(input);
        assertEquals(1300000, encoded.length());
        assertEquals(encoded.length(), new CDATAEncoder().maxEncodedLength(input.length()));

        StringWriter writer = new StringWriter(encoded.length());
        Encode.forCDATA(writer, input);
        assertEquals(encoded, writer.toString());
    }

    public void testCloseSequenceIsRejectedInEveryPosition() throws Exception {
        String[] inputs = {
            "]]>", "a]]>", "]]>b", "a]]>b", "]]>]]>", "x]]>y]]>z",
            "]]" + ">", "]" + "]>",
        };
        for (String input : inputs) {
            assertStringFacadeRejects(input);
            assertWriterFacadeRejects(input);
        }
    }

    public void testIllegalXmlCharactersAreRejected() throws Exception {
        String[] inputs = {
            "\0", "a\0b", "\u0001\u0002", "\u001f", "\u0080", "\u009f",
            "x\u0001", "\u000b", "\u001c",
        };
        for (String input : inputs) {
            assertStringFacadeRejects(input);
            assertWriterFacadeRejects(input);
        }
    }

    public void testMalformedSurrogatesAndNoncharactersAreRejected() throws Exception {
        String[] inputs = {
            "\ud800", "\ud800x", "x\ud800", "\udc00", "x\udc00",
            "\ud800\ud800", "\udc00\udc00", "\ufffe", "\uffff",
            "\ufdd0", "\ufdef", new String(Character.toChars(0x10ffff)),
            new String(Character.toChars(0x1fffe)),
        };
        for (String input : inputs) {
            assertStringFacadeRejects(input);
            assertWriterFacadeRejects(input);
        }
    }

    public void testRejectionLeavesNoOutputBehind() throws Exception {
        StringWriter out = new StringWriter();
        try {
            Encode.forCDATA(out, "safe-prefix\0");
            fail("NUL must be rejected");
        } catch (EncodingException expected) {
            // Fail closed: nothing is written before the validation failure.
        }
        assertEquals("", out.toString());

        try {
            Encode.forCDATA("safe-prefix]]>tail");
            fail("terminator must be rejected");
        } catch (EncodingException expected) {
            // Expected.
        }
    }

    public void testLegalCdataRoundTripsThroughAnXmlParser() throws Exception {
        String[] values = {
            "", "plain text", "<tag> & \"quotes\" 'apos'",
            "]", "]]", "]]]]]", ">", ">>", "]>", ">]",
            "a]b", "a]]b", "a>b", "brackets ] and angle > mixed",
            "line1\nline2\ntab\tend", "\u00e9\u2192\ud83d\ude00",
            new String(Character.toChars(0x10000))
                + new String(Character.toChars(0x1f600)),
            "NEL\u0085 and DEL\u007f stay legal content",
        };
        DocumentBuilder parser = newParser();
        for (String value : values) {
            String encoded = Encode.forCDATA(value);
            assertParsedValue(parser, normalizeLineEndings(value), encoded);

            StringWriter writer = new StringWriter();
            Encode.forCDATA(writer, value);
            assertEquals("writer facade matches string facade", encoded,
                writer.toString());
            assertParsedValue(parser, normalizeLineEndings(value),
                writer.toString());
        }
    }

    public void testEncodedOutputCannotCompleteATrustedBoundary() throws Exception {
        DocumentBuilder parser = newParser();
        // A trusted prefix ending in "]]" must still keep ">" inside the data.
        String encoded = Encode.forCDATA(">");
        Document document = parse(parser,
            "<?xml version=\"1.0\"?><r><![CDATA[]]" + encoded + "]]></r>");
        assertEquals("]]>", document.getDocumentElement().getTextContent());

        // A literal terminator anywhere in the logical input is rejected
        // rather than split into a second document.
        assertStringFacadeRejects("]]>]><safe > ]]>");
        assertWriterFacadeRejects("]]>]><safe > ]]>");
    }

    public void testStreamingWriterRejectsTerminatorSplitAcrossWrites()
            throws Exception {
        String[][] splits = {
            {"]]", ">"}, {"]", "]>"}, {"", "]]", ">"}, {"a]]", ">"},
            {"]", "]", ">"}, {"]]", "", ">"},
        };
        for (String[] writes : splits) {
            StringWriter out = new StringWriter();
            EncodedWriter writer = new EncodedWriter(out, Encoders.CDATA);
            try {
                for (String chunk : writes) {
                    writer.write(chunk);
                }
                writer.close();
                fail("split terminator must be rejected: "
                    + Arrays.toString(writes));
            } catch (EncodingException expected) {
                // Fail closed across write boundaries.
            }
        }
    }

    public void testStreamingWriterRejectsInvalidCharacterAcrossWrites()
            throws Exception {
        StringWriter out = new StringWriter();
        EncodedWriter writer = new EncodedWriter(out, Encoders.CDATA);
        writer.write("safe");
        writer.write("\0");
        try {
            writer.close();
            fail("NUL must be rejected when the stream is finalized");
        } catch (EncodingException expected) {
            // Fail closed: the illegal unit is never copied to the output.
        }
        String produced = out.toString() + pendingBuffer(writer);
        assertEquals("safe", produced);
        assertFalse("NUL must never reach output", produced.contains("\0"));
    }

    /** Reads bytes still held in an EncodedWriter's internal output buffer. */
    private static String pendingBuffer(EncodedWriter writer) throws Exception {
        java.lang.reflect.Field field =
            EncodedWriter.class.getDeclaredField("_buffer");
        field.setAccessible(true);
        CharBuffer buffer = (CharBuffer) field.get(writer);
        return new String(buffer.array(), 0, buffer.position());
    }

    public void testStreamingWriterPreservesLegalSplitWrites() throws Exception {
        String full = "a]b]]c>d";
        String expected = Encode.forCDATA(full);
        StringWriter out = new StringWriter();
        EncodedWriter writer = new EncodedWriter(out, Encoders.CDATA);
        writer.write("a]b");
        writer.write("]]c");
        writer.write(">d");
        writer.close();
        assertEquals(expected, out.toString());
        assertParsedValue(newParser(), full, out.toString());
    }

    public void testLowLevelEncoderRejectsAtEndOfInput() {
        CDATAEncoder encoder = new CDATAEncoder();
        assertLowLevelRejects(encoder, "\0");
        assertLowLevelRejects(encoder, "a\0");
        assertLowLevelRejects(encoder, "\ud800");
        assertLowLevelRejects(encoder, "x\ud800");
        assertLowLevelRejects(encoder, "\udc00");
        assertLowLevelRejects(encoder, "]]>");
        assertLowLevelRejects(encoder, "\uffff");
    }

    public void testEveryRejectionReasonIsReachableFromBothEntryPoints() {
        CDATAEncoder encoder = new CDATAEncoder();
        // One representative for each branch of the shared rejectIllegal
        // classifier: ASCII control, C1 control, BMP noncharacter, dangling
        // high surrogate, stray low surrogate, and a noncharacter pair.
        String[] illegal = {
            "\u0001", "\u0080", "\ufdd0", "\ud800x", "\udc00",
            new String(Character.toChars(0x1ffff)),
        };
        for (String value : illegal) {
            // Validation entry point (String facade pre-scan).
            try {
                encoder.validateInput(value);
                fail("validateInput accepted " + debug(value));
            } catch (EncodingException expected) {
                // Required.
            }
            // Offset-scan entry point used by the Buffer facade.
            try {
                encoder.firstEncodedOffset(value, 0, value.length());
                fail("firstEncodedOffset accepted " + debug(value));
            } catch (EncodingException expected) {
                // Required.
            }
            // Array-backed encoding loop entry point.
            assertLowLevelRejects(encoder, value);
        }
    }

    public void testFirstEncodedOffsetReturnsLocationOfBracketAndAngle() {
        CDATAEncoder encoder = new CDATAEncoder();
        assertEquals(3, encoder.firstEncodedOffset("abc]def", 0, 7));
        assertEquals(2, encoder.firstEncodedOffset("ab>cd", 0, 5));
        assertEquals(5, encoder.firstEncodedOffset("plain", 0, 5));

        // A terminator and an illegal unit encountered during the offset scan
        // are rejected through that entry point, not only the pre-scan.
        try {
            encoder.firstEncodedOffset("ab]]>cd", 0, 7);
            fail("offset scan must reject a literal terminator");
        } catch (EncodingException expected) {
            // Required.
        }
        try {
            encoder.firstEncodedOffset("ab\0cd", 0, 5);
            fail("offset scan must reject an illegal control character");
        } catch (EncodingException expected) {
            // Required.
        }
        // A legal supplementary pair is skipped as a single unit.
        String pair = new String(Character.toChars(0x1f600));
        assertEquals(2 + pair.length(),
            encoder.firstEncodedOffset("ab" + pair, 0, 2 + pair.length()));
    }

    public void testEncoderNameAndAngleOverflowPath() {
        CDATAEncoder encoder = new CDATAEncoder();
        assertEquals("CDATAEncoder", encoder.toString());

        // An output buffer too small for the angle replacement reports an
        // overflow without consuming the input, then succeeds after draining.
        CharBuffer input = CharBuffer.wrap(">".toCharArray());
        CharBuffer output = CharBuffer.allocate(4);
        CoderResult first = encoder.encode(input, output, true);
        assertTrue("angle replacement needs 13 chars", first.isOverflow());
        assertEquals(0, input.position());
        CharBuffer roomy = CharBuffer.allocate(16);
        assertTrue(encoder.encode(input, roomy, true).isUnderflow());
        assertEquals(GT, new String(roomy.array(), 0, roomy.position()));
    }

    public void testC1AndBmpNoncharacterRejectionMessages() {
        CDATAEncoder encoder = new CDATAEncoder();
        assertMessageContains(encoder, "\u0080", "C1 control character");
        assertMessageContains(encoder, "\ufdd0", "noncharacter");
        assertMessageContains(encoder, "\udc00", "low surrogate");
        assertMessageContains(encoder, "\ud800x", "unpaired high surrogate");
    }

    private static void assertMessageContains(CDATAEncoder encoder, String value,
            String fragment) {
        try {
            encoder.validateInput(value);
            fail("accepted " + fragment);
        } catch (EncodingException expected) {
            assertTrue("message should mention " + fragment + " but was "
                    + expected.getMessage(),
                expected.getMessage().contains(fragment));
        }
    }

    public void testLowLevelEncoderRetainsTrailingHighSurrogateThenRejects() {
        CDATAEncoder encoder = new CDATAEncoder();
        CharBuffer input = CharBuffer.wrap("x\ud800".toCharArray());
        CharBuffer output = CharBuffer.allocate(64);
        CoderResult first = encoder.encode(input, output, false);
        assertTrue("high surrogate waits for the next code unit",
            first.isUnderflow());
        assertTrue("high surrogate remains pending", input.hasRemaining());

        try {
            encoder.encode(input, output, true);
            fail("unpaired high surrogate must be rejected at end of input");
        } catch (EncodingException expected) {
            // Expected.
        }
    }

    public void testLowLevelEncoderOverflowThenRejectsWithoutEmittingBadChar() {
        CDATAEncoder encoder = new CDATAEncoder();
        CharBuffer input = CharBuffer.wrap("a\0".toCharArray());
        CharBuffer output = CharBuffer.allocate(8);
        try {
            encoder.encode(input, output, true);
            fail("NUL must be rejected even when output space is tight");
        } catch (EncodingException expected) {
            // A rejection throws before buffer positions are settled, so read
            // the backing array directly: the valid prefix may be present but
            // the NUL must never have been copied into any output slot.
            char[] array = output.array();
            assertEquals('a', array[0]);
            for (int k = 1; k < array.length; ++k) {
                assertEquals("NUL must not reach output slot " + k,
                    0, array[k]);
            }
        }
    }

    public void testAllLegalCodePointsRoundTripWithoutRawTerminator()
            throws Exception {
        DocumentBuilder parser = newParser();
        for (int cp = 0; cp <= Character.MAX_CODE_POINT; ++cp) {
            if (!isLegalCdataCodePoint(cp)) {
                continue;
            }
            String value = new String(Character.toChars(cp));
            String encoded = Encode.forCDATA(value);
            // The close/reopen spelling contains "]]>" as section boundary
            // markup, never as data: wrapping and parsing must reproduce the
            // exact input code point.
            assertParsedValue(parser, normalizeLineEndings(value), encoded);
        }
    }

    private static boolean isLegalCdataCodePoint(int cp) {
        if (cp == 0x9 || cp == 0xA || cp == 0xD) {
            return true;
        }
        if (cp < 0x20) {
            return false;
        }
        if (cp >= 0x7F && cp <= 0x9F && cp != 0x85) {
            return false;
        }
        if (cp >= Character.MIN_SURROGATE && cp <= Character.MAX_SURROGATE) {
            return false;
        }
        if ((cp >= 0xFDD0 && cp <= 0xFDEF) || (cp & 0xFFFE) == 0xFFFE) {
            return false;
        }
        return true;
    }

    private static void assertLowLevelRejects(CDATAEncoder encoder, String value) {
        CharBuffer input = CharBuffer.wrap(value.toCharArray());
        CharBuffer output = CharBuffer.allocate(value.length() * 13 + 4);
        try {
            encoder.encode(input, output, true);
            fail("low-level encoder accepted " + debug(value));
        } catch (EncodingException expected) {
            // Expected.
        }
    }

    private static void assertStringFacadeRejects(String value) {
        try {
            String result = Encode.forCDATA(value);
            fail("forCDATA accepted " + debug(value) + " as " + debug(result));
        } catch (EncodingException expected) {
            // Expected.
        }
    }

    private static void assertWriterFacadeRejects(String value) throws Exception {
        StringWriter out = new StringWriter();
        try {
            Encode.forCDATA(out, value);
            fail("forCDATA(Writer) accepted " + debug(value));
        } catch (EncodingException expected) {
            assertEquals("writer must stay empty on rejection", "",
                out.toString());
        }
    }

    private static DocumentBuilder newParser() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        return factory.newDocumentBuilder();
    }

    private static Document parse(DocumentBuilder parser, String xml)
            throws Exception {
        return parser.parse(new InputSource(new java.io.StringReader(xml)));
    }

    /**
     * XML parsers normalize input line endings to LF on parse, so round-trip
     * comparisons apply the same normalization to the expected value.
     */
    private static String normalizeLineEndings(String value) {
        return value.replace("\r\n", "\n").replace('\r', '\n');
    }

    private static void assertParsedValue(DocumentBuilder parser, String value,
            String encoded) throws Exception {
        Document document = parse(parser,
            "<?xml version=\"1.0\"?><r><![CDATA[" + encoded + "]]></r>");
        assertEquals("round trip for " + debug(value), value,
            document.getDocumentElement().getTextContent());
    }

    private static String debug(String value) {
        StringBuilder builder = new StringBuilder("\"");
        for (int i = 0; i < value.length(); ++i) {
            char ch = value.charAt(i);
            if (ch >= ' ' && ch <= '~') {
                builder.append(ch);
            } else {
                builder.append(String.format("\\u%04x", (int) ch));
            }
        }
        return builder.append('"').toString();
    }

    public void testEncodingExceptionPreservesMessageAndCause() {
        Throwable cause = new IllegalStateException("root");
        EncodingException withCause = new EncodingException("boom", cause);
        assertEquals("boom", withCause.getMessage());
        assertSame(cause, withCause.getCause());

        EncodingException messageOnly = new EncodingException("solo");
        assertEquals("solo", messageOnly.getMessage());
        assertNull(messageOnly.getCause());
    }

    public void testBaseEncoderDefaultsRejectUnsupportedBufferPaths() {
        Encoder bare = new Encoder() {
            @Override
            int maxEncodedLength(int n) {
                return n;
            }

            @Override
            int firstEncodedOffset(String input, int off, int len) {
                return off + len;
            }
        };
        // No input means an immediate underflow without touching the kernel.
        assertTrue(bare.encode(CharBuffer.allocate(0), CharBuffer.allocate(1),
            true).isUnderflow());
        // An array-backed buffer with input dispatches to encodeArrays.
        try {
            bare.encode(CharBuffer.wrap("x".toCharArray()),
                CharBuffer.allocate(4), true);
            fail("default encodeArrays must be unsupported");
        } catch (UnsupportedOperationException expected) {
            // Required.
        }
        // A non-array-backed (read-only) buffer dispatches to encodeBuffers.
        try {
            bare.encode(CharBuffer.wrap("x".toCharArray()).asReadOnlyBuffer(),
                CharBuffer.allocate(4), true);
            fail("read-only input must route to the unsupported buffer path");
        } catch (UnsupportedOperationException expected) {
            // Required.
        }
        // Default encoders accept all input; only CDATA overrides this.
        bare.validateInput("anything");
        assertFalse(bare.canFlushPending('x'));
    }

    public void testEncodedWriterRejectsNullEncoder() {
        try {
            new EncodedWriter(new StringWriter(), (Encoder) null);
            fail("null encoder must be rejected");
        } catch (NullPointerException expected) {
            // Required.
        }
    }

    private static String repeat(char ch, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, ch);
        return new String(chars);
    }

}
