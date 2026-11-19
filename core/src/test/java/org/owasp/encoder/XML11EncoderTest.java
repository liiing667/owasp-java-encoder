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

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.xml.sax.InputSource;

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
                
                // Tab and LF are still passed through unencoded; CR is encoded
                // because an XML 1.1 processor normalizes a literal CR to LF
                .encode("tab-char", "\t", "\t")
                .encode("lf-char", "\n", "\n")
                .encode("cr-char", "&#x0d;", "\r")
                
                // XML 1.1 normalizes NEL (0x85) and LS (0x2028) to LF, so they are encoded
                .encode("nel-char", "&#x85;", "\u0085")
                .encode("line-separator-char", "&#x2028;", "\u2028")
                .encode("mixed-nel-ls", "a&#x85;b&#x2028;c", "a\u0085b\u2028c")
                
                // Combined test
                .encode("mixed-control-chars", "&#x01;a\t&#x7f;b\nc", "\u0001a\t\u007Fb\nc");

            // Define the complete partition before generating the range sweeps.
            builder.encoded(0x01, 0x1f)
                .valid("\t\n")
                .encoded("\r")
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
     * Test that tab and lf are not encoded in XML 1.1, but cr is encoded
     * because an XML 1.1 processor normalizes a literal cr to lf.
     */
    public void testXML11AllowedControlChars() {
        assertEquals("a\tb\nc", Encode.forXml11("a\tb\nc"));
        assertEquals("a&#x0d;b", Encode.forXml11("a\rb"));
        assertEquals("a&#x0d;&#x0d;b", Encode.forXml11("a\r\rb"));
        // a cr-lf pair must keep both characters through parsing
        assertEquals("a&#x0d;\nb", Encode.forXml11("a\r\nb"));
    }
    
    /**
     * Test that C0 control characters (except tab and lf) are encoded in XML 1.1.
     */
    public void testXML11C0ControlChars() {
        // Test each C0 control character
        for (int i = 1; i <= 0x1F; i++) {
            if (i == 0x09 || i == 0x0A) {
                // Tab and LF should not be encoded
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
     * Test that XML 1.0 behavior for CR is unchanged (passed through), while
     * XML 1.1 encodes it.  This pins the version-dependent fail-closed split:
     * the same input is treated according to the selected XML version.
     */
    public void testCRHandlingDependsOnVersion() {
        assertEquals("a\rb", Encode.forXml("a\rb"));
        assertEquals("a&#x0d;b", Encode.forXml11("a\rb"));
        assertEquals("a&#x0d;b", Encode.forXml11Content("a\rb"));
        assertEquals("a&#x0d;b", Encode.forXml11Attribute("a\rb"));
    }

    /**
     * Pinned boundary matrix for the XML 1.1 encoder: each boundary of the
     * character classification is shown with its expected output, including
     * the rejections (invalid characters replaced with a space).
     */
    public void testXML11BoundaryMatrix() {
        String[][] matrix = {
            // C0 controls: null rejected, restricted chars encoded, tab/lf valid
            {"\u0000", " "},
            {"\u0001", "&#x01;"},
            {"\u0008", "&#x08;"},
            {"\t", "\t"},
            {"\n", "\n"},
            {"\u000b", "&#x0b;"},
            {"\u000c", "&#x0c;"},
            {"\r", "&#x0d;"},
            {"\u000e", "&#x0e;"},
            {"\u001f", "&#x1f;"},
            {"\u0020", "\u0020"},
            // DEL and C1 controls: all encoded, including NEL
            {"\u007f", "&#x7f;"},
            {"\u0084", "&#x84;"},
            {"\u0085", "&#x85;"},
            {"\u0086", "&#x86;"},
            {"\u009f", "&#x9f;"},
            {"\u00a0", "\u00a0"},
            // line separator encoded, paragraph separator valid
            {"\u2028", "&#x2028;"},
            {"\u2029", "\u2029"},
            // BMP boundaries around the surrogate range
            {"\ud7ff", "\ud7ff"},
            {"\ue000", "\ue000"},
            // BMP noncharacters: boundary chars kept, noncharacters rejected
            {"\ufdcf", "\ufdcf"},
            {"\ufdd0", " "},
            {"\ufdef", " "},
            {"\ufdf0", "\ufdf0"},
            {"\ufffd", "\ufffd"},
            {"\ufffe", " "},
            {"\uffff", " "},
            // supplementary characters: valid pairs pass through
            {"\ud800\udc00", "\ud800\udc00"},
            {"\ud83f\udffd", "\ud83f\udffd"},
            {"\udbff\udffd", "\udbff\udffd"},
            // supplementary noncharacters rejected (one space per pair)
            {"\ud83f\udffe", " "},
            {"\ud83f\udfff", " "},
            {"\udbff\udffe", " "},
            {"\udbff\udfff", " "},
        };
        for (String[] row : matrix) {
            assertEquals("input " + describe(row[0]),
                row[1], Encode.forXml11(row[0]));
        }
        // lone surrogates are rejected individually
        assertEquals(" ", Encode.forXml11("\ud800"));
        assertEquals(" ", Encode.forXml11("\udfff"));
        assertEquals("a b", Encode.forXml11("a\ud800b"));
        assertEquals("a b", Encode.forXml11("a\udc00b"));
        // high surrogate followed by a valid pair: first rejected, pair kept
        assertEquals(" \ud800\udc00", Encode.forXml11("\ud800\ud800\udc00"));
        // null is rejected even though other C0 controls are encodable
        assertEquals(" ", Encode.forXml11("\u0000"));
    }

    private static String describe(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            b.append(String.format("U+%04X ", (int) s.charAt(i)));
        }
        return b.toString().trim();
    }

    /**
     * Verify that a real XML 1.1 parser preserves the referenced characters in
     * content and both attribute quote styles, for String and Writer APIs.
     */
    public void testXML11ParserRoundTrip() throws Exception {
        String input = "a\u0085b\u2028c\u2029d&<>\"'e\rf";
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
}
