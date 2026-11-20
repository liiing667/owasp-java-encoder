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

/**
 * UrlBoundaryFixture -- runnable fixture that prints the fixed reject and
 * pass cases for the absolute-URL boundary.  Exits with status 1 if any
 * case deviates from its expected outcome.
 *
 * <pre>
 *     java -cp core-classes:test-classes org.owasp.encoder.UrlBoundaryFixture
 * </pre>
 */
public final class UrlBoundaryFixture {
    private UrlBoundaryFixture() {}

    public static void main(String[] args) {
        int failures = 0;

        System.out.println("== reject: non-allowed scheme ==");
        for (String url : UrlBoundaryTest.REJECT_SCHEMES) {
            failures += expectReject(url);
        }
        System.out.println("== reject: userinfo ==");
        for (String url : UrlBoundaryTest.REJECT_USERINFO) {
            failures += expectReject(url);
        }
        System.out.println("== reject: fragment ==");
        for (String url : UrlBoundaryTest.REJECT_FRAGMENTS) {
            failures += expectReject(url);
        }
        System.out.println("== reject: malformed / non-absolute ==");
        for (String url : UrlBoundaryTest.REJECT_MALFORMED) {
            failures += expectReject(url);
        }
        failures += expectReject(null);

        System.out.println("== pass: legitimate https ==");
        for (String url : UrlBoundaryTest.PASS_URLS) {
            failures += expectPass(url);
        }

        System.out.println("== pass: context-encoded output ==");
        failures += expectPass("href",
            UrlBoundary.forHtmlAttribute(
                "https://example.com/search?q=owasp&page=2"));
        failures += expectPass("js",
            UrlBoundary.forJavaScript("https://example.com/it's"));
        failures += expectPass("css",
            UrlBoundary.forCssUrl("https://example.com/a(b)"));

        if (failures != 0) {
            System.out.println("FIXTURE FAILED: " + failures
                + " unexpected outcome(s)");
            System.exit(1);
        }
        System.out.println("FIXTURE OK: all reject/pass cases as expected");
    }

    private static int expectReject(String url) {
        try {
            String out = UrlBoundary.validate(url);
            System.out.println("UNEXPECTED-PASS  " + url + "  ->  " + out);
            return 1;
        } catch (IllegalArgumentException e) {
            System.out.println("REJECT  " + url);
            return 0;
        }
    }

    private static int expectPass(String url) {
        try {
            System.out.println("PASS    " + url + "  ->  "
                + UrlBoundary.validate(url));
            return 0;
        } catch (IllegalArgumentException e) {
            System.out.println("UNEXPECTED-REJECT  " + url);
            return 1;
        }
    }

    private static int expectPass(String label, String encoded) {
        System.out.println("PASS    " + label + "  ->  " + encoded);
        return 0;
    }
}
