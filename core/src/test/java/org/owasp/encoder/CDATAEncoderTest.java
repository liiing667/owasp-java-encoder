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

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Arrays;
import junit.framework.Test;
import junit.framework.TestCase;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * CDATAEncoderTest -- Test the CDATAEncoder for all code-points.
 *
 * @author Jeff Ichnowski
 */
public class CDATAEncoderTest extends TestCase {
    public static Test suite() {
        String rb = "]]>]<![CDATA[";
        String gt = "]]><![CDATA[>";
        return new EncoderTestSuiteBuilder(CDATAEncoderTest.class, new CDATAEncoder(), "-safe-", "-]]>-")
            .encode(rb + rb + gt, "]]>")
            .encode(rb, "]")
            .encode(rb + rb, "]]")
            .encode(rb + rb + gt + rb, "]]>]")
            .encode(rb + rb + gt + rb + gt, "]]>]>")
            .encode(rb + rb + gt + gt, "]]>>")
            .encode(rb + rb + rb + rb + rb, "]]]]]")
            .encode(gt, ">")
            .encode("<\"&'" + gt, "<\"&'>")

            .invalid(0, 0x1f)
            .valid("\t\r\n")
            .valid(' ', Character.MAX_CODE_POINT)
            .encoded("]>")
            .invalid(0x7f, 0x9f)
            .valid("\u0085")
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
            .invalidRejectionSuite()

            .build();
    }

    public void testNullEncodesAsLiteralNullAndRoundTrips() throws Exception {
        assertEquals("null", Encode.forCDATA(null));
        StringWriter writer = new StringWriter();
        Encode.forCDATA(writer, null);
        assertEquals("null", writer.toString());
        assertParsedCdataValue("null", Encode.forCDATA(null));
    }

    public void testIllegalCharactersAreRejectedBeforeOutput() {
        String[] illegalInputs = {
            "\0", "a\0b", "x\037y",
            "a\u007fb", "a\u0080b", "a\u009fb",
            "x\ud800", "\ud800x", "x\udc00", "\udc00x",
            "\ud800\ud800", "\udc00\udc00",
            "a\ufdd0b", "a\ufdefb", "a\ufffeb", "a\uffffb",
            "a\udbff\udfffb", "\udbff\udfff",
        };
        for (String input : illegalInputs) {
            assertRejected(input);
            assertRejectedByWriter(input);
        }
    }

    public void testRejectionMessageNamesTheOffendingIndex() {
        try {
            Encode.forCDATA("ab\0");
            fail("NUL accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("index 2"));
        }
        try {
            Encode.forCDATA("a\ud800b");
            fail("unpaired high surrogate accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("index 1"));
        }
    }

    public void testRejectionIsAtomicAndLeavesWriterUntouched() throws Exception {
        String[] illegalInputs = {
            "\0", "safe text\0", "]]>\0", "\ud800", "a\ufffe",
            "]]>\ud800", "\u007f]]>"
        };
        for (String input : illegalInputs) {
            StringWriter writer = new StringWriter();
            try {
                Encode.forCDATA(writer, input);
                fail("writer accepted illegal input: " + debug(input));
            } catch (IllegalArgumentException expected) {
                assertEquals("writer must stay empty on rejection: " + debug(input),
                    "", writer.toString());
            }
        }
    }

    public void testRejectionAgreesWithEncoderClassificationAcrossTheBmp() {
        CDATAEncoder encoder = new CDATAEncoder();
        char[] pair = new char[2];
        for (int codePoint = 0; codePoint <= Character.MAX_VALUE; codePoint++) {
            String input;
            if (codePoint >= Character.MIN_HIGH_SURROGATE
                    && codePoint <= Character.MAX_LOW_SURROGATE) {
                // Surrogate code units are only legal as a complete pair.
                input = new String(new char[] {(char) codePoint});
            } else {
                input = new String(pair, 0, Character.toChars(codePoint, pair, 0));
            }
            int offset = encoder.firstEncodedOffset(input, 0, input.length());
            boolean encoderSeesUnsafe = offset < input.length()
                && input.charAt(offset) != ']' && input.charAt(offset) != '>';
            boolean rejected;
            try {
                encoder.rejectUnsafeContent(input);
                rejected = false;
            } catch (IllegalArgumentException expected) {
                rejected = true;
            }
            assertEquals("classification mismatch at U+"
                    + Integer.toHexString(codePoint),
                encoderSeesUnsafe, rejected);
        }
    }

    public void testSupplementaryPlanePairsFollowTheSameRule() {
        CDATAEncoder encoder = new CDATAEncoder();
        int[] legalCodePoints = {0x10000, 0x1f600, 0x10fffd, 0xe0000, 0xf0000};
        for (int codePoint : legalCodePoints) {
            String input = new String(Character.toChars(codePoint));
            encoder.rejectUnsafeContent(input);
            assertEquals(input, Encode.forCDATA(input));
        }
        int[] noncharacters = {0x1fffe, 0x1ffff, 0x10fffe, 0x10ffff,
            0x2fffe, 0xeffff};
        for (int codePoint : noncharacters) {
            final String input = new String(Character.toChars(codePoint));
            try {
                encoder.rejectUnsafeContent(input);
                fail("supplementary noncharacter accepted: U+"
                    + Integer.toHexString(codePoint));
            } catch (IllegalArgumentException expected) {
                // fail-closed
            }
        }
    }

    public void testLegalContentRoundTripsThroughAnXmlParser() throws Exception {
        String[] legalInputs = {
            "", "plain text", "<\"&'", "\t\r\n",
            "]", "]]", ">", "]]>", "]]>]><safe",
            "a]]>b<c>&d\"e'f&g",
            "unicode \u00e9\u2028\u2029\u0085",
            "emoji \ud83d\ude00 end",
            "min supplementary \ud800\udc00",
            "high supplementary \udbff\udffd",
            "line1\r\nline2\nline3\r",
            "brackets ]]] >> >]]",
        };
        for (String input : legalInputs) {
            String encoded = Encode.forCDATA(input);
            assertParsedCdataValue(input, encoded);

            StringWriter writer = new StringWriter();
            Encode.forCDATA(writer, input);
            assertEquals("writer facade matches String facade: " + debug(input),
                encoded, writer.toString());
            assertParsedCdataValue(input, writer.toString());
        }
    }

    public void testEncodedFragmentCannotCompleteATrustedBoundary() throws Exception {
        String token = "]]>";
        for (int start = 0; start < token.length(); start++) {
            for (int end = start + 1; end <= token.length(); end++) {
                String trustedPrefix = token.substring(0, start);
                String attacker = token.substring(start, end);
                String trustedSuffix = token.substring(end)
                    + "<evil id='split-pwn'/>";
                String composed = trustedPrefix + Encode.forCDATA(attacker)
                    + trustedSuffix;
                org.w3c.dom.Document document = parseCdataDocument(composed);
                assertEquals("no injected element for split " + start + ":" + end,
                    0, document.getElementsByTagName("evil").getLength());
                assertEquals("parsed value preserved for split " + start + ":" + end,
                    token + "<evil id='split-pwn'/>",
                    document.getDocumentElement().getTextContent());
            }
        }
    }

    public void testEncodedOutputContainsNoRawTerminator() {
        String[] inputs = {"]", "]]", "]]>", ">", "]]>]>", "a]]b>c"};
        for (String input : inputs) {
            String encoded = Encode.forCDATA(input);
            assertNoBareCdataTerminator(encoded, input);
        }
    }

    private static void assertNoBareCdataTerminator(String encoded, String input) {
        // Every occurrence of "]]>" must be the opening half of a close/reopen
        // spelling ("]]>]<![CDATA[" or "]]><![CDATA[") and never a terminator
        // followed by non-CDATA content.
        int index = 0;
        while ((index = encoded.indexOf("]]>", index)) >= 0) {
            assertTrue("bare terminator at " + index + ": " + debug(input),
                encoded.startsWith("]]>]<![CDATA[", index)
                    || encoded.startsWith("]]><![CDATA[", index));
            index += 3;
        }
    }

    private static void assertRejected(String input) {
        try {
            String actual = Encode.forCDATA(input);
            fail("illegal input was encoded as " + debug(actual)
                + " for " + debug(input));
        } catch (IllegalArgumentException expected) {
            // fail-closed rejection
        }
    }

    private static void assertRejectedByWriter(String input) {
        try {
            Encode.forCDATA(new StringWriter(), input);
            fail("writer accepted illegal input: " + debug(input));
        } catch (IllegalArgumentException expected) {
            // fail-closed rejection
        } catch (Exception unexpected) {
            fail("wrong exception type for " + debug(input) + ": " + unexpected);
        }
    }

    private static void assertParsedCdataValue(String expected, String encoded)
            throws Exception {
        org.w3c.dom.Document document = parseCdataDocument(encoded);
        String actual = document.getDocumentElement().getTextContent();
        // XML parsers normalize CRLF and CR to LF.
        assertEquals("round trip for " + debug(expected),
            expected.replace("\r\n", "\n").replace('\r', '\n'),
            actual.replace("\r\n", "\n").replace('\r', '\n'));
    }

    private static org.w3c.dom.Document parseCdataDocument(String encoded)
            throws Exception {
        String xml = "<?xml version='1.0'?><r><![CDATA[" + encoded + "]]></r>";
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setErrorHandler(new DefaultHandler() {
            @Override
            public void error(SAXParseException exception) throws SAXParseException {
                throw exception;
            }

            @Override
            public void fatalError(SAXParseException exception)
                    throws SAXParseException {
                throw exception;
            }
        });
        return builder.parse(new InputSource(new StringReader(xml)));
    }

    private static String debug(String value) {
        StringBuilder builder = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch >= ' ' && ch <= '~') {
                builder.append(ch);
            } else {
                builder.append(String.format("\\u%04x", (int) ch));
            }
        }
        return builder.append('"').toString();
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

    private static String repeat(char ch, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, ch);
        return new String(chars);
    }

}
