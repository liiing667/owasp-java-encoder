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

import java.nio.CharBuffer;
import java.nio.charset.CoderResult;

/**
 * CDATAEncoder -- encoder for CDATA sections. CDATA sections are generally good
 * for including large blocks of text that contain characters that normally
 * require encoding (ampersand, quotes, less-than, etc...). The CDATA context
 * however still does not allow invalid characters, and can be closed by the
 * sequence "]]>". This encoder removes invalid XML characters and represents
 * every {@code "]"} and {@code ">"} with close/reopen sequences. That rule
 * prevents any nonempty encoded substring from completing a {@code "]]>"}
 * delimiter supplied partly by adjacent trusted literal text. Parsed character
 * data is preserved, but a streaming XML consumer must handle multiple CDATA
 * and character-data events.
 *
 * <p>The close/reopen spellings keep every emitted fragment inside its CDATA
 * context, but they can never make an illegal character representable: a NUL,
 * an unpaired surrogate, a control code or a Unicode noncharacter has no legal
 * parsed value in XML 1.0. Streaming callers therefore receive the documented
 * replacement character, while the fixed String facade calls
 * {@link #rejectUnsafeContent} up front and fails closed instead of silently
 * changing the data.</p>
 *
 * @author Jeff Ichnowski
 */
class CDATAEncoder extends Encoder {

    /** A parsed-value-preserving spelling of {@code "]"}. */
    private static final char[] RIGHT_BRACKET_ENCODED
            = "]]>]<![CDATA[".toCharArray();

    /** Length of {@link #RIGHT_BRACKET_ENCODED}. */
    private static final int RIGHT_BRACKET_ENCODED_LENGTH = 13;

    /**
     * A value-preserving spelling of {@code ">"} that remains safe when
     * adjacent trusted CDATA text ends in {@code "]]"}.
     */
    private static final char[] GREATER_THAN_ENCODED
            = "]]><![CDATA[>".toCharArray();

    /** Length of {@link #GREATER_THAN_ENCODED}. */
    private static final int GREATER_THAN_ENCODED_LENGTH = 13;

    /**
     * Fails closed when a complete value cannot be represented safely in a
     * CDATA section. The {@code "]"} and {@code ">"} spellings emitted by
     * {@link #encodeArrays} already neutralize a {@code "]]>"} terminator,
     * including one split across the trusted/encoded boundary; this check
     * instead rejects content that has no legal XML 1.0 representation at all.
     * It is used by the fixed String facade before any output is produced, so
     * a rejection is atomic and never emits a partial, alternative document.
     *
     * @param input the complete value the caller intends to encode
     * @throws IllegalArgumentException if {@code input} contains a NUL, another
     * illegal XML 1.0 character, an unpaired surrogate, or a Unicode
     * noncharacter
     */
    void rejectUnsafeContent(String input) {
        final int n = input.length();
        for (int i = 0; i < n; ++i) {
            char ch = input.charAt(i);
            if (ch <= Unicode.MAX_ASCII) {
                if (ch == ']' || ch == '>'
                        || ch >= ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
                    continue;
                }
            } else if (ch < Character.MIN_HIGH_SURROGATE) {
                if (ch > Unicode.MAX_C1_CTRL_CHAR || ch == Unicode.NEL) {
                    continue;
                }
            } else if (ch <= Character.MAX_HIGH_SURROGATE) {
                if (i + 1 < n && Character.isLowSurrogate(input.charAt(i + 1))) {
                    int codePoint = Character.toCodePoint(ch, input.charAt(i + 1));
                    if (!Unicode.isNonCharacter(codePoint)) {
                        ++i;
                        continue;
                    }
                }
            } else if (// low surrogate without a preceding high surrogate,
                    // or a BMP noncharacter: both have no legal value.
                    ch <= Character.MAX_LOW_SURROGATE
                    || ch > '\ufffd'
                    || ('\ufdd0' <= ch && ch <= '\ufdef')) {
                // fall through to the rejection below
            } else {
                continue;
            }
            throw new IllegalArgumentException(
                "CDATA input contains an illegal XML 1.0 character at index "
                    + i + ": 0x" + Integer.toHexString(ch));
        }
    }

    @Override
    protected int maxEncodedLength(int n) {
        // A lone ']' has the largest per-character replacement.
        if (n > Integer.MAX_VALUE / RIGHT_BRACKET_ENCODED_LENGTH) {
            // The exact result cannot fit in an int (or a Java String).
            return Integer.MAX_VALUE;
        }
        return n * RIGHT_BRACKET_ENCODED_LENGTH;
    }

    @Override
    protected int firstEncodedOffset(String input, int off, int len) {
        final int n = off + len;
        //int closeCount = 0; //unused...
        for (int i = off; i < n; ++i) {
            char ch = input.charAt(i);
            if (ch <= Unicode.MAX_ASCII) {
                if (ch == ']' || ch == '>') {
                    return i;
                } else {
                    if (ch < ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
                        return i;
//                    } else {
//                        // valid
                    }
                }
            } else if (ch < Character.MIN_HIGH_SURROGATE) {
                if (ch <= Unicode.MAX_C1_CTRL_CHAR && ch != Unicode.NEL) {
                    return i;
//                } else {
//                    // valid
                }
            } else if (ch <= Character.MAX_HIGH_SURROGATE) {
                if (i + 1 < n) {
                    if (Character.isLowSurrogate(input.charAt(i + 1))) {
                        int cp = Character.toCodePoint(ch, input.charAt(i + 1));
                        if (Unicode.isNonCharacter(cp)) {
                            return i;
                        } else {
                            ++i;
                            // valid pair
                        }
                    } else {
                        return i;
                    }
                } else {
                    // end of input, high without low = invalid
                    return i;
                }
            } else if (// low surrogate without preceding high surrogate
                    ch <= Character.MAX_LOW_SURROGATE
                    // or non-characters
                    || ch > '\ufffd'
                    || ('\ufdd0' <= ch && ch <= '\ufdef'))
            {
                return i;
//            } else {
//                // valid
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
            char ch = in[i];
            if (ch <= Unicode.MAX_ASCII) {
                if (ch == ']') {
                    if (m - j < RIGHT_BRACKET_ENCODED_LENGTH) {
                        return overflow(input, i, output, j);
                    }
                    System.arraycopy(RIGHT_BRACKET_ENCODED, 0, out, j,
                        RIGHT_BRACKET_ENCODED_LENGTH);
                    j += RIGHT_BRACKET_ENCODED_LENGTH;
                } else if (ch == '>') {
                    if (m - j < GREATER_THAN_ENCODED_LENGTH) {
                        return overflow(input, i, output, j);
                    }
                    System.arraycopy(GREATER_THAN_ENCODED, 0, out, j,
                        GREATER_THAN_ENCODED_LENGTH);
                    j += GREATER_THAN_ENCODED_LENGTH;
                } else {
                    if (j >= m) {
                        return overflow(input, i, output, j);
                    }
                    if (ch >= ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
                        out[j++] = ch;
                    } else {
                        out[j++] = XMLEncoder.INVALID_CHARACTER_REPLACEMENT;
                    }
                }
            } else if (ch < Character.MIN_HIGH_SURROGATE) {
                if (ch > Unicode.MAX_C1_CTRL_CHAR || ch == Unicode.NEL) {
                    if (j >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = ch;
                } else {
                    // C1 control code
                    if (j >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = XMLEncoder.INVALID_CHARACTER_REPLACEMENT;
                }
            } else if (ch <= Character.MAX_HIGH_SURROGATE) {
                if (i + 1 < n) {
                    if (Character.isLowSurrogate(in[i + 1])) {
                        int cp = Character.toCodePoint(ch, in[i + 1]);
                        if (Unicode.isNonCharacter(cp)) {
                            if (j >= m) {
                                return overflow(input, i, output, j);
                            }
                            out[j++] = XMLEncoder.INVALID_CHARACTER_REPLACEMENT;
                            ++i;
                        } else {
                            if (m - j < 2) {
                                return overflow(input, i, output, j);
                            }
                            out[j++] = ch;
                            out[j++] = in[++i];
                        }
                    } else {
                        // high without low
                        if (j >= m) {
                            return overflow(input, i, output, j);
                        }
                        out[j++] = XMLEncoder.INVALID_CHARACTER_REPLACEMENT;
                    }
                } else if (endOfInput) {
                    // end of input, high without low = invalid
                    if (j >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = XMLEncoder.INVALID_CHARACTER_REPLACEMENT;
                } else {
                    break;
                }
            } else if (// low surrogate without preceding high surrogate
                    ch <= Character.MAX_LOW_SURROGATE
                    // or non-characters
                    || ch > '\ufffd'
                    || ('\ufdd0' <= ch && ch <= '\ufdef'))
            {
                if (j >= m) {
                    return overflow(input, i, output, j);
                }
                out[j++] = XMLEncoder.INVALID_CHARACTER_REPLACEMENT;
            } else {
                if (j >= m) {
                    return overflow(input, i, output, j);
                }
                out[j++] = ch;
            }
        }
        return underflow(input, i, output, j);
    }

    @Override
    public String toString() {
        return "CDATAEncoder";
    }
}
