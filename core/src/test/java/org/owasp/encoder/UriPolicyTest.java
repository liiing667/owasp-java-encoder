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

import junit.framework.TestCase;

import java.io.StringWriter;
import java.net.URI;

/**
 * UriPolicyTest -- tests for the policy-based untrusted URL entry point.
 */
public class UriPolicyTest extends TestCase {

    private static UriPolicy httpPolicy() {
        return UriPolicy.builder()
            .allowSchemes("http", "https")
            .build();
    }

    public void testAcceptsAllowedSchemeAndEncodesForHtmlAttribute() {
        UriPolicy policy = httpPolicy();
        String url = "http://www.example.com/search?a=1&b='2'#frag";
        assertEquals(Encode.forHtmlAttribute(url),
            policy.encodeForHtmlAttribute(url));
        assertEquals("http://www.example.com/search?a=1&amp;b=&#39;2&#39;#frag",
            policy.encodeForHtmlAttribute(url));
    }

    public void testWriterOverloadMatchesStringOverload() throws Exception {
        UriPolicy policy = httpPolicy();
        String url = "https://example.com/p?q='x'&r=~y";
        StringWriter out = new StringWriter();
        policy.encodeForHtmlAttribute(out, url);
        assertEquals(policy.encodeForHtmlAttribute(url), out.toString());
    }

    public void testSchemeMatchingIsCaseInsensitive() {
        UriPolicy policy = httpPolicy();
        assertEquals("HTTP://Example.COM/",
            policy.encodeForHtmlAttribute("HTTP://Example.COM/"));
    }

    public void testRejectsDangerousSchemes() {
        UriPolicy policy = httpPolicy();
        assertRejected(policy, "javascript:alert(1)");
        assertRejected(policy, "JavaScript:alert(1)");
        assertRejected(policy, "data:text/html,<script>alert(1)</script>");
        assertRejected(policy, "vbscript:msgbox(1)");
        assertRejected(policy, "file:///etc/passwd");
    }

    public void testRejectsRelativeAndSchemeRelativeUrls() {
        UriPolicy policy = httpPolicy();
        assertRejected(policy, "/absolute/path");
        assertRejected(policy, "relative/path");
        assertRejected(policy, "//example.com/scheme-relative");
        assertRejected(policy, "?query-only");
        assertRejected(policy, "#fragment-only");
    }

    public void testRejectsUserinfo() {
        UriPolicy policy = httpPolicy();
        assertRejected(policy, "http://user@example.com/");
        assertRejected(policy, "http://user:pass@example.com/");
        assertRejected(policy, "https://user:pass@example.com:443/p");
    }

    public void testRejectsMalformedPorts() {
        UriPolicy policy = httpPolicy();
        assertRejected(policy, "http://example.com:abc/");
        assertRejected(policy, "http://example.com:-1/");
        assertRejected(policy, "http://example.com:80x/");
        assertRejected(policy, "http://example.com:99999/");
        assertRejected(policy, "http://:80/");
    }

    public void testAcceptsValidPorts() {
        UriPolicy policy = httpPolicy();
        assertEquals("http://example.com:80/",
            policy.encodeForHtmlAttribute("http://example.com:80/"));
        assertEquals("https://example.com:65535/",
            policy.encodeForHtmlAttribute("https://example.com:65535/"));
        assertEquals("http://example.com:0/",
            policy.encodeForHtmlAttribute("http://example.com:0/"));
    }

    public void testRejectsUnparseableUrls() {
        UriPolicy policy = httpPolicy();
        assertRejected(policy, "http://example.com/pa th");
        assertRejected(policy, "http://exa mple.com/");
        assertRejected(policy, "http://example.com/{");
        assertRejected(policy, "");
    }

    public void testHostAllowList() {
        UriPolicy policy = UriPolicy.builder()
            .allowSchemes("https")
            .allowHosts("www.example.com", "cdn.example.com")
            .build();
        assertEquals("https://www.example.com/a",
            policy.encodeForHtmlAttribute("https://www.example.com/a"));
        assertEquals("https://CDN.EXAMPLE.COM/a",
            policy.encodeForHtmlAttribute("https://CDN.EXAMPLE.COM/a"));
        assertRejected(policy, "https://evil.example.com/");
        assertRejected(policy, "https://example.com/");
        assertRejected(policy, "https://www.example.com.evil.com/");
        // Host allow-list requires an authority even for allowed schemes.
        assertRejected(policy, "https:path-only");
    }

    public void testEmptyHostAllowListAcceptsAnyValidHost() {
        UriPolicy policy = httpPolicy();
        assertEquals("https://anything.example.org:8443/x?y#z",
            policy.encodeForHtmlAttribute(
                "https://anything.example.org:8443/x?y#z"));
    }

    public void testValidateReturnsParsedUri() {
        URI uri = httpPolicy().validate("https://example.com/p?q=1");
        assertEquals("https", uri.getScheme());
        assertEquals("example.com", uri.getHost());
    }

    public void testNullUrlThrowsNullPointerException() {
        try {
            httpPolicy().encodeForHtmlAttribute(null);
            fail("expected NullPointerException");
        } catch (NullPointerException expected) {
        }
    }

    public void testBuildRequiresScheme() {
        try {
            UriPolicy.builder().build();
            fail("expected IllegalStateException");
        } catch (IllegalStateException expected) {
        }
    }

    public void testBuilderRejectsNullAndEmptyValues() {
        try {
            UriPolicy.builder().allowSchemes((String[]) null);
            fail("expected NullPointerException");
        } catch (NullPointerException expected) {
        }
        try {
            UriPolicy.builder().allowSchemes((String) null);
            fail("expected NullPointerException");
        } catch (NullPointerException expected) {
        }
        try {
            UriPolicy.builder().allowSchemes("");
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
        try {
            UriPolicy.builder().allowHosts("");
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
    }

    public void testAllowListsAreExposedAndImmutable() {
        UriPolicy policy = UriPolicy.builder()
            .allowSchemes("HTTPS")
            .allowHosts("Example.COM")
            .build();
        assertTrue(policy.allowedSchemes().contains("https"));
        assertTrue(policy.allowedHosts().contains("example.com"));
        try {
            policy.allowedSchemes().add("http");
            fail("expected UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
        }
        try {
            policy.allowedHosts().add("other.example.com");
            fail("expected UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
        }
    }

    public void testPolicyIsReusableAcrossThreads() throws Exception {
        final UriPolicy policy = httpPolicy();
        final String url = "http://example.com/&'~";
        final String expected = policy.encodeForHtmlAttribute(url);
        Thread[] threads = new Thread[4];
        final AssertionError[] failure = new AssertionError[1];
        for (int i = 0; i < threads.length; ++i) {
            threads[i] = new Thread(new Runnable() {
                public void run() {
                    try {
                        for (int j = 0; j < 100; ++j) {
                            assertEquals(expected,
                                policy.encodeForHtmlAttribute(url));
                        }
                    } catch (AssertionError e) {
                        failure[0] = e;
                    }
                }
            });
            threads[i].start();
        }
        for (Thread thread : threads) {
            thread.join();
        }
        if (failure[0] != null) {
            throw failure[0];
        }
    }

    private static void assertRejected(UriPolicy policy, String url) {
        try {
            policy.encodeForHtmlAttribute(url);
            fail("expected IllegalArgumentException for: " + url);
        } catch (IllegalArgumentException expected) {
        }
    }
}
