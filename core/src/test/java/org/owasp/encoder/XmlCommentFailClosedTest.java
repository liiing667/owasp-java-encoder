// Copyright (c) 2026 OWASP.
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
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import junit.framework.TestCase;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * Fixtures for the fail-closed {@code Encode.forXmlComment} boundary:
 * malicious comment rejection, the empty comment policy, and the
 * compatible output retained for accepted input.
 */
public class XmlCommentFailClosedTest extends TestCase {

    public void testHyphenRunsAndNestedCommentMarkersRejected() {
        String[] malicious = {
            "--", "---", "a--b", "trail--",
            "<!--", "-->", "x<!--y", "x-->y",
            "<!-- nested -- comment -->",
        };
        for (String input : malicious) {
            assertRejected(input);
        }
    }

    public void testInvalidCharactersRejected() {
        String[] malicious = {
            "\u0000", "ok\b", "\u0008", "\u000b",
            "\u007f", "\u0084", "\u0086", "\u009f",
            "\ufdd0", "\ufdef", "\ufffe", "\uffff",
            "\ud800", "\udc00", "ok\ud800x",
            "\ud83f\udffe",
        };
        for (String input : malicious) {
            assertRejected(input);
        }
    }

    public void testWriterFailsBeforeAnyOutput() throws Exception {
        StringWriter out = new StringWriter();
        try {
            Encode.forXmlComment(out, "ok--boom");
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
        assertEquals("no output may precede the failure", "", out.toString());

        out = new StringWriter();
        try {
            Encode.forXmlComment(out, "ok\b");
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
        assertEquals("no output may precede the failure", "", out.toString());
    }

    public void testEmptyCommentPolicy() throws Exception {
        assertEquals("", Encode.forXmlComment(""));

        StringWriter out = new StringWriter();
        Encode.forXmlComment(out, "");
        assertEquals("", out.toString());

        org.w3c.dom.Document parsed = parseXml(
            "<?xml version='1.0'?><r><!--" + Encode.forXmlComment("")
                + "--></r>");
        assertEquals("r", parsed.getDocumentElement().getTagName());
    }

    public void testCompatibleOutputForAcceptedInput() throws Exception {
        assertEquals("safe text", Encode.forXmlComment("safe text"));
        assertEquals("a ~ b", Encode.forXmlComment("a - b"));
        assertEquals("~x", Encode.forXmlComment("-x"));
        assertEquals("trail~", Encode.forXmlComment("trail-"));
        assertEquals("<\"&'>", Encode.forXmlComment("<\"&'>"));
        assertEquals("a\tb\nc\rd", Encode.forXmlComment("a\tb\nc\rd"));
        assertEquals("\u0085", Encode.forXmlComment("\u0085"));
        assertEquals("null", Encode.forXmlComment(null));

        org.w3c.dom.Document parsed = parseXml(
            "<?xml version='1.0'?><r><!-- " + Encode.forXmlComment("a - b")
                + " --></r>");
        assertEquals("r", parsed.getDocumentElement().getTagName());
    }

    public void testOrdinaryXmlContentEncodingUnchanged() {
        assertEquals("1 &lt; 2 -- ok", Encode.forXml("1 < 2 -- ok"));
        assertEquals("a--b", Encode.forXmlContent("a--b"));
        assertEquals("&lt;!-- --&gt;", Encode.forXmlContent("<!-- -->"));
    }

    private static void assertRejected(String input) {
        try {
            Encode.forXmlComment(input);
            fail("expected IllegalArgumentException for input");
        } catch (IllegalArgumentException expected) {
        }
    }

    private static org.w3c.dom.Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setErrorHandler(new DefaultHandler() {
            @Override
            public void error(SAXParseException exception)
                    throws SAXParseException {
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
}
