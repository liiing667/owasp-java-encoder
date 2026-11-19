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

import java.nio.CharBuffer;
import java.nio.charset.CoderResult;

/**
 * JSONEncoder -- Encoder for the contents of a JSON string literal
 * (RFC 8259).  The caller supplies the surrounding double quotes.
 *
 * <p>Encodes {@code "} and {@code \} with a backslash, the control
 * characters U+0000 to U+001F with the short escapes {@code \b},
 * {@code \t}, {@code \n}, {@code \f}, {@code \r} or a <code>&#92;u00xx</code>
 * escape, and {@code <}, {@code >}, {@code &}, U+2028, U+2029 and
 * unpaired surrogates with a <code>&#92;uxxxx</code> escape using lowercase hex.
 * Everything else, including valid surrogate pairs, is passed through
 * unchanged.</p>
 *
 * <p>A high surrogate at the end of the input is only encoded when
 * {@code endOfInput} is true.  Otherwise it is left in the input buffer
 * until the next character shows whether it is part of a pair.</p>
 *
 * <p>The {@link Encode#forJsonText(String)} facade is fail-closed: it runs
 * {@link #validateText(String)} over the complete input before any output
 * is produced and rejects JSON text containing raw control characters or
 * unpaired surrogates with an {@link IllegalArgumentException}.  This
 * streaming encoder retains the escape-everything behavior for callers
 * that cannot validate up front.</p>
 */
class JSONEncoder extends Encoder {

    /**
     * The length of a Unicode escape, e.g. "\\u003c".
     */
    static final int U_ESCAPE_LENGTH = 6;

    /**
     * Fail-closed validation for the {@code Encode.forJsonText} facade.
     * The whole input is scanned so that a rejection happens before any
     * output is produced.  A {@code null} input is accepted because the
     * facade substitutes the literal {@code "null"}, which is legal JSON
     * text.
     *
     * <p>JSON text exchanged between systems must be Unicode encoded in
     * UTF-8 (RFC 8259).  Raw control characters U+0000 to U+001F are not
     * legal anywhere in JSON text, and an unpaired surrogate has no UTF-8
     * representation, so neither can re-embed and re-parse identically.
     * Everything else, including {@code "}, {@code \}, U+2028 and U+2029,
     * is legal JSON text that the encoder escapes for the nested string
     * context while preserving the decoded value.</p>
     *
     * @param json the JSON text to validate
     * @throws IllegalArgumentException if the JSON text contains a raw
     * control character U+0000 to U+001F or an unpaired surrogate
     */
    static void validateText(String json) {
        if (json == null) {
            return;
        }
        final int n = json.length();
        for (int i = 0; i < n; ++i) {
            char ch = json.charAt(i);
            if (ch < ' ') {
                throw new IllegalArgumentException(String.format(
                    "JSON text contains illegal raw control character "
                        + "0x%02X at offset %d; control characters must be "
                        + "escaped in JSON text (RFC 8259)", (int) ch, i));
            }
            if (Character.isHighSurrogate(ch)) {
                if (i + 1 < n && Character.isLowSurrogate(json.charAt(i + 1))) {
                    ++i;
                } else {
                    throw unpairedSurrogate(i, ch);
                }
            } else if (Character.isLowSurrogate(ch)) {
                throw unpairedSurrogate(i, ch);
            }
        }
    }

    /**
     * Builds the rejection for an unpaired surrogate in JSON text.
     *
     * @param offset the offset of the offending code unit in the input
     * @param ch the unpaired surrogate code unit
     * @return the exception to throw
     */
    private static IllegalArgumentException unpairedSurrogate(int offset, char ch) {
        return new IllegalArgumentException(String.format(
            "JSON text contains unpaired surrogate 0x%04X at offset %d; "
                + "it has no UTF-8 representation and cannot round-trip",
            (int) ch, offset));
    }

    @Override
    protected int maxEncodedLength(int n) {
        // "\\u####"
        return n * U_ESCAPE_LENGTH;
    }

    /**
     * Returns true if the character is always encoded, regardless of the
     * characters around it.  Surrogates are handled separately.
     *
     * @param ch the character to check
     * @return true if {@code ch} must be escaped
     */
    private static boolean alwaysEncoded(char ch) {
        if (ch < ' ') {
            return true;
        }
        switch (ch) {
            case '\"':
            case '\\':
            case '<':
            case '>':
            case '&':
            case '\u2028':
            case '\u2029':
                return true;
            default:
                return false;
        }
    }

    @Override
    protected int firstEncodedOffset(String input, int off, int len) {
        final int n = off + len;
        for (int i = off; i < n; ++i) {
            char ch = input.charAt(i);
            if (Character.isHighSurrogate(ch)) {
                if (i + 1 < n && Character.isLowSurrogate(input.charAt(i + 1))) {
                    // valid pair, passed through unchanged
                    ++i;
                } else {
                    return i;
                }
            } else if (Character.isLowSurrogate(ch) || alwaysEncoded(ch)) {
                return i;
            }
        }
        return n;
    }

    @Override
    protected CoderResult encodeArrays(CharBuffer input, CharBuffer output, boolean endOfInput) {
        final char[] in = input.array();
        final char[] out = output.array();
        int i = input.arrayOffset() + input.position();
        final int n = input.arrayOffset() + input.limit();
        int j = output.arrayOffset() + output.position();
        final int m = output.arrayOffset() + output.limit();

        for (; i < n; ++i) {
            final char ch = in[i];

            if (Character.isHighSurrogate(ch)) {
                if (i + 1 < n) {
                    if (Character.isLowSurrogate(in[i + 1])) {
                        // valid surrogate pair, passed through unchanged
                        if (j + 1 >= m) {
                            return overflow(input, i, output, j);
                        }
                        out[j++] = ch;
                        out[j++] = in[++i];
                        continue;
                    }
                    // unpaired high surrogate, falls through to the escape
                } else if (!endOfInput) {
                    // need the next character to see if this is a pair
                    break;
                }
            } else if (!Character.isLowSurrogate(ch) && !alwaysEncoded(ch)) {
                if (j >= m) {
                    return overflow(input, i, output, j);
                }
                out[j++] = ch;
                continue;
            }

            switch (ch) {
                case '\"':
                case '\\':
                    if (j + 1 >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = ch;
                    break;
                case '\b':
                    if (j + 1 >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = 'b';
                    break;
                case '\t':
                    if (j + 1 >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = 't';
                    break;
                case '\n':
                    if (j + 1 >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = 'n';
                    break;
                case '\f':
                    if (j + 1 >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = 'f';
                    break;
                case '\r':
                    if (j + 1 >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = 'r';
                    break;
                default:
                    // other controls, <, >, &, U+2028, U+2029 and
                    // unpaired surrogates
                    if (j + U_ESCAPE_LENGTH > m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = '\\';
                    out[j++] = 'u';
                    out[j++] = HEX[ch >>> 3 * HEX_SHIFT];
                    out[j++] = HEX[(ch >>> 2 * HEX_SHIFT) & HEX_MASK];
                    out[j++] = HEX[(ch >>> HEX_SHIFT) & HEX_MASK];
                    out[j++] = HEX[ch & HEX_MASK];
                    break;
            }
        }

        return underflow(input, i, output, j);
    }

    @Override
    public String toString() {
        return "JSONEncoder";
    }
}
