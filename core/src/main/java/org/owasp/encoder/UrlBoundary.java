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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * UrlBoundary -- validation boundary for absolute URLs built from untrusted
 * input (for example a redirect target supplied by a user).
 *
 * <p>Contextual encoders such as {@link Encode#forUriComponent(String)} do
 * not interpret the value they encode: a {@code javascript:} URL is encoded
 * "correctly" and still executes when the browser dereferences it, and the
 * scheme and userinfo of an absolute URL remain under the browser's control.
 * Encoding alone is therefore not a safe boundary for whole URLs.  This
 * class closes that gap by validating the structure of an absolute URL
 * <i>before</i> it is encoded for the target context:</p>
 *
 * <ul>
 *   <li>The input must parse as a {@link java.net.URI}; malformed input is
 *   rejected.</li>
 *   <li>The URI must be absolute and hierarchical (a scheme followed by
 *   {@code //authority}); relative references, scheme-relative references
 *   and opaque URIs are rejected.</li>
 *   <li>The scheme must be in the allowed set (case-insensitive).  The
 *   {@link #DEFAULT_ALLOWED_SCHEMES default} allows only {@code https};
 *   pass an explicit set to {@link #validate(String, Set)} to permit
 *   additional schemes such as {@code http}.</li>
 *   <li>Userinfo ({@code https://user@host/}) is rejected, so an attacker
 *   cannot smuggle a different apparent origin into the authority.</li>
 *   <li>Fragments ({@code #...}) are rejected; a redirect target has no
 *   legitimate need to carry one across this boundary.</li>
 *   <li>A server-based authority with a parseable host is required, and
 *   ports above 65535 are rejected.</li>
 * </ul>
 *
 * <p>All failures are fail-closed: invalid input raises
 * {@link IllegalArgumentException} and never produces output.  Valid input
 * is returned in normalized ASCII form ({@link URI#toASCIIString()}) and may
 * then be emitted through the matching contextual encoder:
 * {@link #forHtmlAttribute(String)} for {@code href} and {@code src}
 * attributes, {@link #forCssUrl(String)} for CSS {@code url(...)}, and
 * {@link #forJavaScript(String)} for JavaScript string literals.  Use
 * {@link #validate(String)} directly when the URL is emitted into a context
 * that needs no further encoding, such as an HTTP {@code Location} header.</p>
 *
 * <pre>
 *     String target = UrlBoundary.validate(request.getParameter("next"));
 *     response.sendRedirect(target);
 *
 *     &lt;a href="&lt;%=UrlBoundary.forHtmlAttribute(next)%&gt;"&gt;continue&lt;/a&gt;
 * </pre>
 *
 * @author OWASP
 */
public final class UrlBoundary {

    /**
     * Schemes allowed by default: {@code https} only.  Comparison is
     * case-insensitive; the set itself is stored lowercase.
     */
    public static final Set<String> DEFAULT_ALLOWED_SCHEMES =
        Collections.unmodifiableSet(schemeSet("https"));

    /** No instances. */
    private UrlBoundary() {}

    /**
     * Validates an absolute URL against the {@link
     * #DEFAULT_ALLOWED_SCHEMES default allowed schemes} and returns its
     * normalized ASCII form.
     *
     * @param url the untrusted absolute URL
     * @return the normalized absolute URL, safe to emit after contextual
     *     encoding
     * @throws IllegalArgumentException if the URL is malformed, not
     *     absolute, uses a disallowed scheme, or carries userinfo or a
     *     fragment
     */
    public static String validate(String url) {
        return validate(url, DEFAULT_ALLOWED_SCHEMES);
    }

    /**
     * Validates an absolute URL against an explicit set of allowed schemes.
     *
     * @param url the untrusted absolute URL
     * @param allowedSchemes lowercase-insensitive scheme allowlist, for
     *     example {@code new java.util.HashSet<String>(java.util.Arrays.asList("https", "http"))}
     * @return the normalized absolute URL, safe to emit after contextual
     *     encoding
     * @throws IllegalArgumentException if the URL fails any structural check
     *     or its scheme is not allowed
     */
    public static String validate(String url, Set<String> allowedSchemes) {
        if (url == null) {
            throw new IllegalArgumentException("url must not be null");
        }
        if (allowedSchemes == null || allowedSchemes.isEmpty()) {
            throw new IllegalArgumentException(
                "allowedSchemes must not be null or empty");
        }
        final URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("malformed URI: " + url, e);
        }
        if (!uri.isAbsolute() || uri.isOpaque()) {
            throw new IllegalArgumentException(
                "URL must be an absolute, hierarchical URI: " + url);
        }
        Set<String> allowed = schemeSet(
            allowedSchemes.toArray(new String[allowedSchemes.size()]));
        if (!allowed.contains(
                uri.getScheme().toLowerCase(Locale.ENGLISH))) {
            throw new IllegalArgumentException(
                "scheme not allowed: " + uri.getScheme());
        }
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException(
                "userinfo is not allowed: " + url);
        }
        if (uri.getRawFragment() != null) {
            throw new IllegalArgumentException(
                "fragments are not allowed: " + url);
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException(
                "URL must have a server-based authority with a host: " + url);
        }
        if (uri.getPort() > 65535) {
            throw new IllegalArgumentException(
                "port out of range: " + url);
        }
        return uri.toASCIIString();
    }

    /**
     * Validates an absolute URL and encodes it for an HTML attribute
     * context such as {@code <a href="...">}.
     *
     * @param url the untrusted absolute URL
     * @return the validated URL encoded with
     *     {@link Encode#forHtmlAttribute(String)}
     * @throws IllegalArgumentException if the URL fails validation
     */
    public static String forHtmlAttribute(String url) {
        return Encode.forHtmlAttribute(validate(url));
    }

    /**
     * See {@link #forHtmlAttribute(String)}; validates against an explicit
     * scheme allowlist.
     *
     * @param url the untrusted absolute URL
     * @param allowedSchemes scheme allowlist
     * @return the validated URL encoded for an HTML attribute
     * @throws IllegalArgumentException if the URL fails validation
     */
    public static String forHtmlAttribute(String url, Set<String> allowedSchemes) {
        return Encode.forHtmlAttribute(validate(url, allowedSchemes));
    }

    /**
     * Validates an absolute URL and encodes it for a CSS {@code url(...)}
     * context.
     *
     * @param url the untrusted absolute URL
     * @return the validated URL encoded with {@link Encode#forCssUrl(String)}
     * @throws IllegalArgumentException if the URL fails validation
     */
    public static String forCssUrl(String url) {
        return Encode.forCssUrl(validate(url));
    }

    /**
     * See {@link #forCssUrl(String)}; validates against an explicit scheme
     * allowlist.
     *
     * @param url the untrusted absolute URL
     * @param allowedSchemes scheme allowlist
     * @return the validated URL encoded for a CSS URL context
     * @throws IllegalArgumentException if the URL fails validation
     */
    public static String forCssUrl(String url, Set<String> allowedSchemes) {
        return Encode.forCssUrl(validate(url, allowedSchemes));
    }

    /**
     * Validates an absolute URL and encodes it for a JavaScript string
     * literal context.
     *
     * @param url the untrusted absolute URL
     * @return the validated URL encoded with
     *     {@link Encode#forJavaScript(String)}
     * @throws IllegalArgumentException if the URL fails validation
     */
    public static String forJavaScript(String url) {
        return Encode.forJavaScript(validate(url));
    }

    /**
     * See {@link #forJavaScript(String)}; validates against an explicit
     * scheme allowlist.
     *
     * @param url the untrusted absolute URL
     * @param allowedSchemes scheme allowlist
     * @return the validated URL encoded for a JavaScript string context
     * @throws IllegalArgumentException if the URL fails validation
     */
    public static String forJavaScript(String url, Set<String> allowedSchemes) {
        return Encode.forJavaScript(validate(url, allowedSchemes));
    }

    /** Builds a lowercase set from the given scheme names. */
    private static Set<String> schemeSet(String... schemes) {
        Set<String> set = new LinkedHashSet<String>();
        for (String scheme : schemes) {
            set.add(scheme.toLowerCase(Locale.ENGLISH));
        }
        return set;
    }
}
