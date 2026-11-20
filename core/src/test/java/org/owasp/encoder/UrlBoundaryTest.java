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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * UrlBoundaryTest -- fixed fixtures for the absolute-URL validation
 * boundary: disallowed schemes, userinfo, fragments and malformed URIs
 * fail closed; legitimate HTTPS pages pass and are contextually encoded.
 */
public class UrlBoundaryTest extends TestCase {
    public static Test suite() {
        return new TestSuite(UrlBoundaryTest.class);
    }

    static final String[] PASS_URLS = {
        "https://example.com/",
        "https://example.com/path/to/page",
        "https://example.com/search?q=owasp&page=2",
        "https://example.com:8443/secure",
        "https://sub.domain.example.co.uk/a/b/c",
        "HTTPS://EXAMPLE.COM/UPPER",
        "https://example.com/%e4%b8%ad%e6%96%87",
        "https://user-name.example.com/path;param?x=1&y=2",
    };

    static final String[] REJECT_SCHEMES = {
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
        "ftp://example.com/",
        "http://example.com/",
        "mailto:attacker@example.com",
    };

    static final String[] REJECT_USERINFO = {
        "https://user@example.com/",
        "https://user:password@example.com/",
        "https://example.com@evil.example/",
        "https://example.com:443@evil.example/",
    };

    static final String[] REJECT_FRAGMENTS = {
        "https://example.com/#fragment",
        "https://example.com/page#",
        "https://example.com/#javascript:alert(1)",
    };

    static final String[] REJECT_MALFORMED = {
        "",
        "not a url",
        "https://exa mple.com/",
        "https://example.com/%zz",
        "https://[::1",
        "https://example.com:99999/",
        "https://example.com:abc/",
        "https:///path-only",
        "https:opaque-no-authority",
        "//example.com/scheme-relative",
        "/relative/path",
        "https://example.com\\@evil.example/",
    };

    public void testLegitimateHttpsUrlsPass() {
        for (String url : PASS_URLS) {
            String validated = UrlBoundary.validate(url);
            assertNotNull(validated);
            assertTrue(validated.toLowerCase().startsWith("https://"));
        }
        assertEquals("https://example.com/",
            UrlBoundary.validate("https://example.com/"));
        assertEquals("https://example.com/search?q=owasp&page=2",
            UrlBoundary.validate("https://example.com/search?q=owasp&page=2"));
    }

    public void testNonAllowedSchemesFailClosed() {
        for (String url : REJECT_SCHEMES) {
            assertRejected(url);
        }
    }

    public void testUserInfoFailsClosed() {
        for (String url : REJECT_USERINFO) {
            assertRejected(url);
        }
    }

    public void testFragmentsFailClosed() {
        for (String url : REJECT_FRAGMENTS) {
            assertRejected(url);
        }
    }

    public void testMalformedUrisFailClosed() {
        for (String url : REJECT_MALFORMED) {
            assertRejected(url);
        }
        try {
            UrlBoundary.validate(null);
            fail("null must be rejected");
        } catch (IllegalArgumentException expected) {
        }
    }

    public void testExplicitSchemeAllowlist() {
        Set<String> httpAndHttps = new HashSet<String>(
            Arrays.asList("http", "https"));
        assertEquals("http://example.com/",
            UrlBoundary.validate("http://example.com/", httpAndHttps));
        assertEquals("https://example.com/",
            UrlBoundary.validate("https://example.com/", httpAndHttps));
        try {
            UrlBoundary.validate("ftp://example.com/", httpAndHttps);
            fail("ftp must remain rejected");
        } catch (IllegalArgumentException expected) {
        }
    }

    public void testTargetContextEncodingAfterValidation() {
        assertEquals("https://example.com/search?q=owasp&amp;page=2",
            UrlBoundary.forHtmlAttribute(
                "https://example.com/search?q=owasp&page=2"));
        assertEquals("https:\\/\\/example.com\\/it\\x27\\x73",
            UrlBoundary.forJavaScript("https://example.com/it's"));
        assertEquals("https:\\2f\\2f example.com\\2f a\\28 b\\29",
            UrlBoundary.forCssUrl("https://example.com/a(b)"));
    }

    static void assertRejected(String url) {
        try {
            String out = UrlBoundary.validate(url);
            fail("expected rejection for <" + url + "> but got <" + out + ">");
        } catch (IllegalArgumentException expected) {
        }
    }
}
