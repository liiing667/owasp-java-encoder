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

import java.io.StringWriter;
import junit.framework.TestCase;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;

/**
 * Parser-oracle tests for {@link Encode#forHtmlUnquotedAttribute(String)}
 * rendered into a fixed HTML fragment. Attack values must not create
 * additional attributes, compatible values must survive unchanged, and
 * empty input must keep the attribute boundary well-formed.
 */
public class UnquotedAttributeFragmentTest extends TestCase {

    /**
     * Values that would break out of an unquoted attribute if any of
     * their characters were emitted literally.
     */
    private static final String[] ATTACK_VALUES = {
        "x onmouseover=alert(1)",
        "a=b",
        "c\\",
        "foo\\bar",
        "`",
        "\"",
        "'",
        "/",
        "<script>alert(1)</script>",
        "&",
        " x",
        "x ",
        "\t\n\r\f ",
        "foo bar=baz\\qux",
        "1`onfocus=alert(1)",
    };

    /**
     * Values that contain no characters requiring encoding and must pass
     * through verbatim so existing templates keep working.
     */
    private static final String[] COMPATIBLE_VALUES = {
        "safe",
        "hello-world",
        "foo.bar",
        "a[b]",
        "x_1",
        "{ok}",
        "~tilde",
        "café",
        "中文",
    };

    private static Element parseValue(String encoded, String suffix) {
        String fragment = "<input value=" + encoded + suffix + ">";
        Element input = Jsoup.parse(fragment).select("input").first();
        assertNotNull("fragment did not produce an <input>: " + fragment,
            input);
        return input;
    }

    public void testAttackValuesCannotCreateNewAttributes() {
        for (String attack : ATTACK_VALUES) {
            String encoded = Encode.forHtmlUnquotedAttribute(attack);
            Element input = parseValue(encoded, "");
            assertEquals("attribute count for " + attack,
                1, input.attributes().size());
            assertEquals("round-trip value for " + attack,
                attack, input.attr("value"));
        }
    }

    public void testAttackValuesCannotSwallowFollowingAttribute() {
        for (String attack : ATTACK_VALUES) {
            String encoded = Encode.forHtmlUnquotedAttribute(attack);
            Element input = parseValue(encoded, " disabled");
            assertEquals("attribute count for " + attack,
                2, input.attributes().size());
            assertEquals("round-trip value for " + attack,
                attack, input.attr("value"));
            assertTrue("disabled attribute lost for " + attack,
                input.hasAttr("disabled"));
        }
    }

    public void testCompatibleValuesPassThroughUnchanged() {
        for (String compatible : COMPATIBLE_VALUES) {
            String encoded = Encode.forHtmlUnquotedAttribute(compatible);
            assertEquals("encoding changed compatible value " + compatible,
                compatible, encoded);
            Element input = parseValue(encoded, " disabled");
            assertEquals("attribute count for " + compatible,
                2, input.attributes().size());
            assertEquals("round-trip value for " + compatible,
                compatible, input.attr("value"));
        }
    }

    public void testEmptyValueKeepsAttributeBoundary() {
        assertEquals("\"\"", Encode.forHtmlUnquotedAttribute(""));
        Element input = parseValue(Encode.forHtmlUnquotedAttribute(""),
            " disabled");
        assertEquals(2, input.attributes().size());
        assertEquals("", input.attr("value"));
        assertTrue(input.hasAttr("disabled"));
    }

    public void testNullValueFollowsLibraryWidePolicy() {
        assertEquals("null", Encode.forHtmlUnquotedAttribute(null));
        Element input = parseValue(Encode.forHtmlUnquotedAttribute(null), "");
        assertEquals(1, input.attributes().size());
        assertEquals("null", input.attr("value"));
    }

    public void testWriterOverloadMatchesStringOverload() throws Exception {
        String[] values = new String[ATTACK_VALUES.length
            + COMPATIBLE_VALUES.length + 2];
        System.arraycopy(ATTACK_VALUES, 0, values, 0, ATTACK_VALUES.length);
        System.arraycopy(COMPATIBLE_VALUES, 0, values,
            ATTACK_VALUES.length, COMPATIBLE_VALUES.length);
        values[values.length - 2] = "";
        values[values.length - 1] = null;
        for (String value : values) {
            StringWriter out = new StringWriter();
            Encode.forHtmlUnquotedAttribute(out, value);
            assertEquals("writer output for " + value,
                Encode.forHtmlUnquotedAttribute(value), out.toString());
        }
    }
}
