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

import java.io.IOException;
import java.io.Writer;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * UriPolicy -- allow-list based validation for complete untrusted URLs,
 * combined with encoding for a quoted HTML attribute.  This is the
 * recommended replacement for the deprecated {@link Encode#forUri(String)}
 * when an entire URL comes from an untrusted source:
 *
 * <pre>
 *     private static final UriPolicy LINKS = UriPolicy.builder()
 *         .allowSchemes("http", "https")
 *         .allowHosts("www.example.com", "cdn.example.com")
 *         .build();
 *
 *     &lt;a href="&lt;%=LINKS.encodeForHtmlAttribute(userUrl)%&gt;"&gt;...&lt;/a&gt;
 * </pre>
 *
 * <p>A URL is accepted only when all of the following hold:</p>
 * <ul>
 *   <li>It parses as a {@link java.net.URI} without error.</li>
 *   <li>Its scheme is present and in the configured scheme allow-list
 *   (compared case-insensitively).  Relative and scheme-relative
 *   ({@code //host/...}) URLs are therefore rejected.</li>
 *   <li>It contains no userinfo component
 *   (for example {@code http://user:pass@host/} is rejected).</li>
 *   <li>If an authority component is present, it must parse as a
 *   server-based authority with a non-empty host, and the port, when
 *   present, must be between 0 and 65535.  Malformed ports such as
 *   {@code http://host:abc/} are rejected.</li>
 *   <li>If at least one allowed host is configured, an authority with a
 *   host in the host allow-list (compared case-insensitively) must be
 *   present.  If no hosts are configured, any syntactically valid host
 *   is accepted.</li>
 * </ul>
 *
 * <p>Validation rejects with {@link IllegalArgumentException}; it never
 * attempts to repair or normalize a rejected URL.  Accepted URLs are
 * encoded with {@link Encode#forHtmlAttribute(String)} for safe placement
 * inside a quoted HTML attribute.  Note that this policy performs
 * syntactic validation only: it does not resolve or fetch the URL, and
 * an allowed scheme/host combination does not imply the target is
 * trustworthy.  Instances are immutable and safe to share between
 * threads.</p>
 */
public final class UriPolicy {
    /** Maximum valid TCP/UDP port number. */
    private static final int MAX_PORT = 65535;

    /** Lower-cased allowed schemes; never empty. */
    private final Set<String> schemes;
    /** Lower-cased allowed hosts; empty means any host. */
    private final Set<String> hosts;

    private UriPolicy(Builder builder) {
        schemes = Collections.unmodifiableSet(
            new LinkedHashSet<String>(builder.schemes));
        hosts = Collections.unmodifiableSet(
            new LinkedHashSet<String>(builder.hosts));
    }

    /**
     * Creates a new builder.  At least one scheme must be configured
     * before {@link Builder#build()} is called.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the allowed schemes, in lower case, in the order they were
     * added.
     *
     * @return the immutable scheme allow-list
     */
    public Set<String> allowedSchemes() {
        return schemes;
    }

    /**
     * Returns the allowed hosts, in lower case, in the order they were
     * added.  An empty set means any syntactically valid host is
     * accepted.
     *
     * @return the immutable host allow-list
     */
    public Set<String> allowedHosts() {
        return hosts;
    }

    /**
     * Validates the given URL against this policy.
     *
     * @param url the untrusted URL to validate
     * @return the parsed URI for callers that also need the components
     * @throws NullPointerException if url is null
     * @throws IllegalArgumentException if the URL is malformed or
     * violates this policy
     */
    public URI validate(String url) {
        Objects.requireNonNull(url, "url");
        final URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(
                "URL rejected: cannot be parsed: " + e.getMessage(), e);
        }

        String scheme = uri.getScheme();
        if (scheme == null
            || !schemes.contains(scheme.toLowerCase(Locale.ROOT)))
        {
            throw new IllegalArgumentException(
                "URL rejected: scheme not allowed: " + safe(scheme));
        }

        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException(
                "URL rejected: userinfo is not allowed");
        }

        if (uri.getRawAuthority() != null) {
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                // Server-based authority parsing failed; typically a
                // malformed port (e.g. "host:abc") or empty host.
                throw new IllegalArgumentException(
                    "URL rejected: malformed authority or port: "
                        + safe(uri.getRawAuthority()));
            }
            int port = uri.getPort();
            if (port < -1 || port > MAX_PORT) {
                throw new IllegalArgumentException(
                    "URL rejected: port out of range: " + port);
            }
            if (!hosts.isEmpty()
                && !hosts.contains(host.toLowerCase(Locale.ROOT)))
            {
                throw new IllegalArgumentException(
                    "URL rejected: host not allowed: " + safe(host));
            }
        } else if (!hosts.isEmpty()) {
            throw new IllegalArgumentException(
                "URL rejected: an allowed host is required");
        }

        return uri;
    }

    /**
     * Validates the given URL against this policy and encodes it for a
     * quoted HTML attribute with
     * {@link Encode#forHtmlAttribute(String)}.
     *
     * @param url the untrusted URL to validate and encode
     * @return the validated URL encoded for an HTML attribute
     * @throws NullPointerException if url is null
     * @throws IllegalArgumentException if the URL is malformed or
     * violates this policy
     */
    public String encodeForHtmlAttribute(String url) {
        validate(url);
        return Encode.forHtmlAttribute(url);
    }

    /**
     * See {@link #encodeForHtmlAttribute(String)}.  This version writes
     * directly to a Writer without an intervening string.
     *
     * @param out where to write encoded output
     * @param url the untrusted URL to validate and encode
     * @throws NullPointerException if out or url is null
     * @throws IllegalArgumentException if the URL is malformed or
     * violates this policy
     * @throws IOException if thrown by writer
     */
    public void encodeForHtmlAttribute(Writer out, String url)
        throws IOException
    {
        validate(url);
        Encode.forHtmlAttribute(out, url);
    }

    /** Renders a rejected component without control characters. */
    private static String safe(String component) {
        if (component == null) {
            return "(none)";
        }
        StringBuilder sb = new StringBuilder(component.length());
        for (int i = 0; i < component.length(); ++i) {
            char ch = component.charAt(i);
            sb.append(ch < 0x20 || ch == 0x7f ? '?' : ch);
        }
        return sb.toString();
    }

    /**
     * Builder for {@link UriPolicy}.  Scheme and host names are matched
     * case-insensitively and stored lower-cased.
     */
    public static final class Builder {
        private final Set<String> schemes = new LinkedHashSet<String>();
        private final Set<String> hosts = new LinkedHashSet<String>();

        private Builder() {}

        /**
         * Adds schemes to the allow-list, for example
         * {@code allowSchemes("http", "https")}.  At least one scheme is
         * required.
         *
         * @param values the schemes to allow
         * @return this builder
         * @throws NullPointerException if values or any element is null
         * @throws IllegalArgumentException if a scheme is empty
         */
        public Builder allowSchemes(String... values) {
            addAll(schemes, values, "scheme");
            return this;
        }

        /**
         * Adds hosts to the allow-list, for example
         * {@code allowHosts("www.example.com")}.  Matching is exact and
         * case-insensitive; subdomains are not implied.  When no hosts
         * are configured, any syntactically valid host is accepted.
         *
         * @param values the hosts to allow
         * @return this builder
         * @throws NullPointerException if values or any element is null
         * @throws IllegalArgumentException if a host is empty
         */
        public Builder allowHosts(String... values) {
            addAll(hosts, values, "host");
            return this;
        }

        /**
         * Builds the immutable policy.
         *
         * @return the policy
         * @throws IllegalStateException if no schemes were configured
         */
        public UriPolicy build() {
            if (schemes.isEmpty()) {
                throw new IllegalStateException(
                    "at least one allowed scheme is required");
            }
            return new UriPolicy(this);
        }

        private static void addAll(Set<String> target, String[] values,
            String what)
        {
            Objects.requireNonNull(values, what + "s");
            for (String value : values) {
                Objects.requireNonNull(value, what);
                String normalized = value.toLowerCase(Locale.ROOT);
                if (normalized.isEmpty()) {
                    throw new IllegalArgumentException(
                        "empty " + what + " is not allowed");
                }
                target.add(normalized);
            }
        }
    }
}
