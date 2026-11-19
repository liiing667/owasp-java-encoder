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

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * XML11EncoderTest -- test suite for the XML 1.1 encoder.
 *
 * @author Jeff Ichnowski
 */
public class XML11EncoderTest extends TestCase {
    
    public XML11EncoderTest(String testName) {
        super(testName);
    }
    
    public static Test suite() {
        TestSuite suite = new TestSuite(XML11EncoderTest.class);
        for (XMLEncoder.Mode mode : XMLEncoder.Mode.values()) {
            XMLEncoder encoder = new XMLEncoder(mode, XMLEncoder.Version.XML_1_1);
            EncoderTestSuiteBuilder builder = new EncoderTestSuiteBuilder(encoder, "-safe-", "-&-")
                .encode("safe", "safe")
                .encode("unencoded &amp; encoded", "unencoded & encoded")
                .encode("valid-surrogate-pair", "\ud800\udc00", "\ud800\udc00")
                .encode("missing-low-surrogate", " ", "\ud800")
                .encode("missing-high-surrogate", " ", "\udc00")
                .encode("valid-upper-char", "\ufffd", "\ufffd")
                .encode("invalid-upper-char", " ", "\uffff")
                
                // XML 1.1 specific: control characters are encoded, not replaced
                .encode("control-char-0x01", "&#x01;", "\u0001")
                .encode("control-char-0x02", "&#x02;", "\u0002")
                .encode("control-char-0x08", "&#x08;", "\u0008")
                .encode("control-char-0x0B", "&#x0b;", "\u000B")
                .encode("control-char-0x0C", "&#x0c;", "\u000C")
                .encode("control-char-0x0E", "&#x0e;", "\u000E")
                .encode("control-char-0x1F", "&#x1f;", "\u001F")
                
                // C1 control characters (0x7F-0x9F) should be encoded in XML 1.1
                .encode("control-char-0x7F", "&#x7f;", "\u007F")
                .encode("control-char-0x80", "&#x80;", "\u0080")
                .encode("control-char-0x9F", "&#x9f;", "\u009F")
                
                // Tab, LF, CR are still passed through unencoded
                .encode("tab-char", "\t", "\t")
                .encode("lf-char", "\n", "\n")
                .encode("cr-char", "\r", "\r")
                
                // XML 1.1 normalizes NEL (0x85) and LS (0x2028) to LF, so they are encoded
                .encode("nel-char", "&#x85;", "\u0085")
                .encode("line-separator-char", "&#x2028;", "\u2028")
                .encode("mixed-nel-ls", "a&#x85;b&#x2028;c", "a\u0085b\u2028c")
                
                // Combined test
                .encode("mixed-control-chars", "&#x01;a\t&#x7f;b\nc", "\u0001a\t\u007Fb\nc")

                // C0 range boundaries: the first and last restricted control
                // code, the whitespace holes that must stay literal, and the
                // first printable code.
                .encode("c0-null-rejected", " ", "\u0000")
                .encode("c0-lower-edge", "&#x01;", "\u0001")
                .encode("c0-before-tab", "&#x08;", "\u0008")
                .encode("c0-after-cr", "&#x0e;", "\u000E")
                .encode("c0-upper-edge", "&#x1f;", "\u001F")
                .encode("c0-first-printable", " ", " ")

                // C1 range boundaries and the internal NEL hole.
                .encode("c1-lower-edge", "&#x7f;", "\u007F")
                .encode("c1-before-nel", "&#x84;", "\u0084")
                .encode("c1-after-nel", "&#x86;", "\u0086")
                .encode("c1-upper-edge", "&#x9f;", "\u009F")
                .encode("c1-first-text", "\u00a0", "\u00a0")

                // Surrogate boundaries: valid text just outside the block, each
                // surrogate edge rejected, and a well-formed pair kept verbatim.
                .encode("before-surrogate-block", "\ud7ff", "\ud7ff")
                .encode("first-high-surrogate-rejected", " ", "\ud800")
                .encode("last-high-surrogate-rejected", " ", "\udbff")
                .encode("first-low-surrogate-rejected", " ", "\udc00")
                .encode("last-low-surrogate-rejected", " ", "\udfff")
                .encode("after-surrogate-block", "\ue000", "\ue000")

                // Noncharacter boundaries must be rejected while neighboring
                // assigned characters remain intact.
                .encode("nonchar-fdd0-rejected", " ", "\ufdd0")
                .encode("nonchar-fdef-rejected", " ", "\ufdef")
                .encode("after-nonchar-block", "\ufdf0", "\ufdf0")
                .encode("nonchar-fffe-rejected", " ", "\ufffe")
                .encode("nonchar-ffff-rejected", " ", "\uffff")

                // A supplementary noncharacter pair is rejected as a unit, a
                // valid supplementary pair is preserved, and a high surrogate
                // followed by a non-low code unit cannot merge into text.
                .encode("supplementary-nonchar-pair-rejected", " ", "\udbff\udffe")
                .encode("supplementary-valid-pair-kept",
                    new String(Character.toChars(0x1f600)),
                    new String(Character.toChars(0x1f600)))
                .encode("high-then-control-not-a-pair", " &#x01;", "\ud800\u0001")

                // Combinations prove a control or surrogate code unit never
                // changes how the adjacent unit is classified.
                .encode("control-before-valid-pair",
                    "&#x01;\ud800\udc00", "\u0001\ud800\udc00")
                .encode("valid-pair-before-control",
                    "\ud800\udc00&#x7f;", "\ud800\udc00\u007F")
                .encode("nul-bounded-surrogates", "  ", "\u0000\ud800")
                .encode("two-lone-surrogates", "  ", "\udc00\ud800");

            // Define the complete partition before generating the range sweeps.
            builder.encoded(0x01, 0x1f)
                .valid("\t\r\n")
                .valid(' ', Character.MAX_CODE_POINT)
                .encoded(0x7f, 0x9f)
                .encoded("\u2028")
                .invalid(0x00, 0x00)
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
                .invalid(0x10fffe, 0x10ffff);

            switch (mode) {
            case ALL:
                builder.encoded("&><\'\"")
                    .encode("&amp;", "&")
                    .encode("&gt;", ">")
                    .encode("&lt;", "<")
                    .encode("&#39;", "\'")
                    .encode("&#34;", "\"");
                break;
            case CONTENT:
                builder.encoded("&><")
                    .encode("&amp;", "&")
                    .encode("&gt;", ">")
                    .encode("&lt;", "<")
                    .encode("\'", "\'")
                    .encode("\"", "\"");
                break;
            case ATTRIBUTE:
                builder.encoded("&<\'\"")
                    .encode("&amp;", "&")
                    .encode(">", ">")
                    .encode("&lt;", "<")
                    .encode("&#39;", "\'")
                    .encode("&#34;", "\"");
                break;
            case SINGLE_QUOTED_ATTRIBUTE:
                builder.encoded("&<\'")
                    .encode("&amp;", "&")
                    .encode(">", ">")
                    .encode("&lt;", "<")
                    .encode("&#39;", "\'")
                    .encode("\"", "\"");
                break;
            case DOUBLE_QUOTED_ATTRIBUTE:
                builder.encoded("&<\"")
                    .encode("&amp;", "&")
                    .encode(">", ">")
                    .encode("&lt;", "<")
                    .encode("\'", "\'")
                    .encode("&#34;", "\"");
                break;
            default:
                throw new AssertionError("untested mode: "+mode);
            }

            suite.addTest(builder
                .validSuite()
                .invalidSuite(XMLEncoder.INVALID_CHARACTER_REPLACEMENT)
                .encodedSuite()
                .build());
        }
        return suite;
    }
    
    /**
     * Test that the public API methods work correctly for XML 1.1.
     */
    public void testXML11PublicAPI() {
        String input = "test\u0001\u0002&<>\"'";

        assertEquals("test&#x01;&#x02;&amp;&lt;&gt;&#34;&#39;", Encode.forXml11(input));
        assertEquals("test&#x01;&#x02;&amp;&lt;&gt;\"'", Encode.forXml11Content(input));
        assertEquals("test&#x01;&#x02;&amp;&lt;>&#34;&#39;", Encode.forXml11Attribute(input));
    }

    /**
     * Test all XML 1.1 Writer overloads with mode-specific escaping.
     */
    public void testXML11PublicAPIWriter() throws IOException {
        String input = "test\u0001\u0002&<>\"'";
        StringWriter writer = new StringWriter();
        Encode.forXml11(writer, input);
        assertEquals("test&#x01;&#x02;&amp;&lt;&gt;&#34;&#39;", writer.toString());

        writer = new StringWriter();
        Encode.forXml11Content(writer, input);
        assertEquals("test&#x01;&#x02;&amp;&lt;&gt;\"'", writer.toString());

        writer = new StringWriter();
        Encode.forXml11Attribute(writer, input);
        assertEquals("test&#x01;&#x02;&amp;&lt;>&#34;&#39;", writer.toString());
    }

    /**
     * Test that tab, lf, and cr are not encoded in XML 1.1.
     */
    public void testXML11AllowedControlChars() {
        String input = "a\tb\nc\rd";
        String result = Encode.forXml11(input);
        assertEquals("a\tb\nc\rd", result);
    }
    
    /**
     * Test that C0 control characters (except tab, lf, cr) are encoded in XML 1.1.
     */
    public void testXML11C0ControlChars() {
        // Test each C0 control character
        for (int i = 1; i <= 0x1F; i++) {
            if (i == 0x09 || i == 0x0A || i == 0x0D) {
                // Tab, LF, CR should not be encoded
                continue;
            }
            char ch = (char) i;
            String input = "a" + ch + "b";
            String result = Encode.forXml11(input);
            String expected = "a&#x" + String.format("%02x", i) + ";b";
            assertEquals("C0 control char 0x" + Integer.toHexString(i) + " should be encoded", 
                        expected, result);
        }
    }
    
    /**
     * Test that DEL and all C1 control characters (including NEL) are encoded in XML 1.1.
     */
    public void testXML11C1ControlChars() {
        // Test DEL and C1 control characters
        for (int i = 0x7F; i <= 0x9F; i++) {
            char ch = (char) i;
            String input = "a" + ch + "b";
            String result = Encode.forXml11(input);
            String expected = "a&#x" + String.format("%02x", i) + ";b";
            assertEquals("C1 control char 0x" + String.format("%02x", i) + " should be encoded", 
                        expected, result);
        }
    }
    
    /**
     * Test that NEL (0x85) is encoded as a character reference in XML 1.1.
     */
    public void testXML11NEL() {
        String input = "a\u0085b";
        assertEquals("a&#x85;b", Encode.forXml11(input));
        assertEquals("a&#x85;b", Encode.forXml11Content(input));
        assertEquals("a&#x85;b", Encode.forXml11Attribute(input));
    }

    /**
     * Test that LINE SEPARATOR (0x2028) is encoded as a character reference in XML 1.1,
     * while PARAGRAPH SEPARATOR (0x2029) is passed through.
     */
    public void testXML11LineSeparator() {
        String input = "a\u2028b\u2029c";
        assertEquals("a&#x2028;b\u2029c", Encode.forXml11(input));
        assertEquals("a&#x2028;b\u2029c", Encode.forXml11Content(input));
        assertEquals("a&#x2028;b\u2029c", Encode.forXml11Attribute(input));
    }

    /**
     * Test that XML 1.0 behavior for NEL and LS is unchanged (passed through).
     */
    public void testXML10NELAndLineSeparatorUnchanged() {
        assertEquals("a\u0085b\u2028c", Encode.forXml("a\u0085b\u2028c"));
    }

    /**
     * Verify that a real XML 1.1 parser preserves the referenced characters in
     * content and both attribute quote styles, for String and Writer APIs.
     */
    public void testXML11ParserRoundTrip() throws Exception {
        String input = "a\u0085b\u2028c\u2029d&<>\"'";
        assertXML11RoundTrip(input, Encode.forXml11(input), Encode.forXml11(input));
        assertXML11RoundTrip(input, Encode.forXml11Content(input), Encode.forXml11Attribute(input));

        StringWriter general = new StringWriter();
        StringWriter content = new StringWriter();
        StringWriter attribute = new StringWriter();
        Encode.forXml11(general, input);
        Encode.forXml11Content(content, input);
        Encode.forXml11Attribute(attribute, input);
        assertXML11RoundTrip(input, general.toString(), general.toString());
        assertXML11RoundTrip(input, content.toString(), attribute.toString());
    }

    private void assertXML11RoundTrip(String expected, String content, String attribute)
            throws Exception {
        String xml = "<?xml version=\"1.1\"?><root double=\"" + attribute
            + "\" single='" + attribute + "'>" + content + "</root>";
        Element root = DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(new InputSource(new StringReader(xml))).getDocumentElement();
        assertEquals("content", expected, root.getTextContent());
        assertEquals("double-quoted attribute", expected, root.getAttribute("double"));
        assertEquals("single-quoted attribute", expected, root.getAttribute("single"));
    }

    /**
     * Test that maxEncodedLength allows 8 characters per input character for
     * XML 1.1, and that the encoded output for LS (the longest reference,
     * {@code &#x2028;}) fits within the value it returns.
     */
    public void testXML11MaxEncodedLength() throws Exception {
        XMLEncoder encoder = new XMLEncoder(XMLEncoder.Mode.ALL, XMLEncoder.Version.XML_1_1);
        assertEquals(8 * 3, encoder.maxEncodedLength(3));
        String input = "\u2028\u2028\u2028";
        java.io.StringWriter out = new java.io.StringWriter();
        Encode.forXml11(out, input);
        assertEquals("&#x2028;&#x2028;&#x2028;", out.toString());
        assertTrue(out.toString().length() <= encoder.maxEncodedLength(input.length()));
    }

    /**
     * The XML 1.1 decision is version-specific: the same restricted control
     * code must be emitted as a character reference only for the XML 1.1
     * encoder. The XML 1.0 encoder keeps its replacement contract instead of
     * borrowing the 1.1 spelling.
     */
    public void testVersionSelectsRestrictedCharacterHandling() {
        String restricted = "a\u0001\u007F\u0085\u2028b";
        assertEquals("a&#x01;&#x7f;&#x85;&#x2028;b", Encode.forXml11(restricted));
        // XML 1.0 replaces the restricted C0/C1 controls with spaces, but
        // leaves NEL and line separator as ordinary (normalizable) text.
        assertEquals("a  \u0085\u2028b", Encode.forXml(restricted));
        // NEL and LS are ordinary text for XML 1.0, but every C0/C1 control
        // other than tab/LF/CR is replaced rather than referenced.
        assertEquals("a\u0085b\u2028c", Encode.forXml("a\u0085b\u2028c"));
        assertEquals("a b", Encode.forXml("a\u0001b"));
    }

    /**
     * Fail-closed range contract over every UTF-16 code unit: encoded output
     * never contains a literal restricted control code, a lone surrogate, or
     * a surrogate pair that encodes a noncharacter. Tab, LF and CR are the
     * only control codes allowed to remain literal.
     */
    public void testXML11OutputNeverContainsForbiddenLiteralUnits() {
        XMLEncoder encoder = new XMLEncoder(XMLEncoder.Mode.ALL,
            XMLEncoder.Version.XML_1_1);
        for (int unit = 0; unit <= Character.MAX_VALUE; unit++) {
            String output = Encode.encode(encoder, String.valueOf((char) unit));
            for (int i = 0; i < output.length(); i++) {
                char ch = output.charAt(i);
                if (ch < 0x20) {
                    assertTrue("literal C0 control U+" + Integer.toHexString(unit),
                        ch == '\t' || ch == '\n' || ch == '\r');
                }
                assertFalse("literal C1 control from U+" + Integer.toHexString(unit),
                    ch >= 0x7F && ch <= 0x9F);
                assertNotLineSeparator(unit, ch);
                if (Character.isHighSurrogate(ch)) {
                    assertTrue("lone high surrogate from U+" + Integer.toHexString(unit),
                        i + 1 < output.length()
                            && Character.isLowSurrogate(output.charAt(i + 1)));
                    int codePoint = Character.toCodePoint(ch, output.charAt(i + 1));
                    assertFalse("noncharacter pair from U+" + Integer.toHexString(unit),
                        Unicode.isNonCharacter(codePoint));
                    i++;
                } else {
                    assertFalse("lone low surrogate from U+"
                        + Integer.toHexString(unit), Character.isLowSurrogate(ch));
                }
            }
        }
    }

    private static void assertNotLineSeparator(int sourceUnit, char ch) {
        if (ch == Unicode.LINE_SEPARATOR) {
            fail("literal line separator from U+" + Integer.toHexString(sourceUnit));
        }
    }

    /**
     * Legal Unicode text, including supplementary characters expressed as
     * surrogate pairs, must survive encoding unchanged rather than being
     * over-escaped or replaced.
     */
    public void testLegalUnicodeTextIsPreserved() {
        String legal = "abc\u00e9\u4e2d\ud800\udc00"
            + new String(Character.toChars(0x1F600)) + "\u2029\ufffd";
        assertEquals(legal, Encode.forXml11(legal));
        assertEquals(legal, Encode.forXml11Content(legal));
        assertEquals(legal, Encode.forXml11Attribute(legal));
        // The first and last characters of the supplementary range are kept.
        assertEquals(new String(Character.toChars(0x10000)),
            Encode.forXml11(new String(Character.toChars(0x10000))));
        assertEquals(new String(Character.toChars(0x10FFFD)),
            Encode.forXml11(new String(Character.toChars(0x10FFFD))));
    }

    /**
     * Restricted controls are emitted as ASCII character references, so the
     * security-critical encoding survives lossy output charsets. Rejected
     * input becomes an ASCII space and never produces a replacement question
     * mark or an unencodable surrogate.
     */
    public void testFailClosedOutputIsSerializableToAscii() {
        String input = "\u0001\u007F\u0085\u2028\u0000\ud800\udbff\udffe\ufffe";
        String encoded = Encode.forXml11(input);
        byte[] ascii = encoded.getBytes(StandardCharsets.US_ASCII);
        assertEquals(encoded, new String(ascii, StandardCharsets.US_ASCII));
        byte[] latin1 = encoded.getBytes(StandardCharsets.ISO_8859_1);
        assertEquals(encoded, new String(latin1, StandardCharsets.ISO_8859_1));
        for (int i = 0; i < encoded.length(); i++) {
            char ch = encoded.charAt(i);
            assertTrue("non-ASCII unit U+" + Integer.toHexString(ch),
                ch < 0x80 || Character.isHighSurrogate(ch)
                    || Character.isLowSurrogate(ch));
        }
    }

    /**
     * Version and range fail together: an XML 1.1 restricted-character
     * reference placed in an XML 1.0 document is rejected by the parser
     * instead of being silently interpreted as different text.
     */
    public void testXml11ReferencesAreRejectedInXml10Document() throws Exception {
        String encoded = Encode.forXml11("x\u0001\u007Fy");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder silentBuilder = factory.newDocumentBuilder();
        silentBuilder.setErrorHandler(new DefaultHandler());
        boolean rejected = false;
        try {
            silentBuilder.parse(new InputSource(
                new StringReader("<?xml version=\"1.0\"?><r>" + encoded + "</r>")));
        } catch (SAXParseException expected) {
            rejected = true;
        }
        assertTrue("XML 1.0 parser must reject XML 1.1 control references",
            rejected);
        // The same payload is well-formed and round-trips in an XML 1.1 doc.
        Element root = silentBuilder.parse(new InputSource(
            new StringReader("<?xml version=\"1.1\"?><r>" + encoded + "</r>")))
            .getDocumentElement();
        assertEquals("x\u0001\u007Fy", root.getTextContent());
    }

    /**
     * Streaming must apply the same version/range decision as the String
     * facade, including when a surrogate pair or a control/surrogate boundary
     * is split across writes and across the writer's internal buffering.
     */
    public void testXML11StreamingMatchesWholeStringAcrossSplits()
            throws IOException {
        String[] probes = {
            "\ud800\udc00", "\udbff\udffe", "\ud800", "\udc00",
            "a\u0001\ud800\udc00b", "\ud800\u007f\udc00", "\udc00\ud800\udc00",
            "\u0000\udbff\udfff", "\u2028\u0085\ud800\udc00",
            repeat('a', 1024) + "\ud800\udc00\u0001",
        };
        for (String input : probes) {
            String expected = Encode.forXml11(input);
            for (int split = 0; split <= input.length(); split++) {
                StringWriter output = new StringWriter();
                EncodedWriter writer = new EncodedWriter(output, Encoders.XML_11);
                writer.write(input, 0, split);
                writer.write(input, split, input.length() - split);
                writer.close();
                assertEquals("split " + split + " of " + input.length(),
                    expected, output.toString());
            }
        }
    }

    /**
     * A high surrogate held pending at an explicit flush cannot be emitted as
     * a lone surrogate. It stays pending until its low surrogate arrives, and
     * is replaced with a space if the stream ends without one.
     */
    public void testPendingSurrogateFlushIsFailClosed() throws IOException {
        StringWriter output = new StringWriter();
        EncodedWriter writer = new EncodedWriter(output, Encoders.XML_11);
        writer.write("a\ud800");
        writer.flush();
        assertEquals("pending high surrogate stays hidden", "a",
            output.toString());
        writer.write("\udc00b");
        writer.close();
        assertEquals("a\ud800\udc00b", output.toString());

        output = new StringWriter();
        writer = new EncodedWriter(output, Encoders.XML_11);
        writer.write("c\ud800");
        writer.flush();
        writer.close();
        assertEquals("unpaired high surrogate is replaced", "c ",
            output.toString());
    }

    private static String repeat(char ch, int count) {
        char[] chars = new char[count];
        java.util.Arrays.fill(chars, ch);
        return new String(chars);
    }
}
