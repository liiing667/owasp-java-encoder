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
 * XMLCommentEncoder -- Encodes for the XML comment context. The sequence
 * "--" is not allowed in XML comments. Every input hyphen is replaced so it
 * cannot combine with a hyphen in adjacent trusted literal text. As with all
 * XML-based contexts, invalid XML characters are not allowed.
 *
 * <p>The {@link Encode#forXmlComment(String)} facade is fail-closed: it
 * runs {@link #validate(String)} over the complete input before any output
 * is produced and rejects hyphen runs ("--", which also covers the nested
 * comment markers "&lt;!--" and "--&gt;") and invalid XML characters with
 * an {@link IllegalArgumentException}. This streaming encoder retains the
 * lossy replacement behavior for callers that cannot validate up front.</p>
 *
 * @author Jeff Ichnowski
 */
class XMLCommentEncoder extends Encoder {

    /**
     * This is the character used to replace every input hyphen.
     */
    static final char HYPHEN_REPLACEMENT = '~';

    /**
     * Fail-closed validation for the {@code Encode.forXmlComment} facade.
     * The whole input is scanned so that a rejection happens before any
     * output is produced. A {@code null} input is accepted because the
     * facade substitutes the literal {@code "null"}, which is valid.
     *
     * @param input the comment text to validate
     * @throws IllegalArgumentException if the input contains "--" (which
     * subsumes the nested comment markers "&lt;!--" and "--&gt;") or a
     * character that is not valid in XML 1.0
     */
    static void validate(String input) {
        if (input == null) {
            return;
        }
        final int n = input.length();
        for (int i = 0; i < n; ++i) {
            char ch = input.charAt(i);
            if (ch == '-') {
                if (i + 1 < n && input.charAt(i + 1) == '-') {
                    throw new IllegalArgumentException(
                        "XML comment input must not contain \"--\" "
                            + "(offset " + i + "); this also rejects the "
                            + "nested comment markers \"<!--\" and \"-->\"");
                }
            } else if (ch <= Unicode.MAX_ASCII) {
                if (ch < ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
                    throw invalidCharacter(i, ch);
                }
            } else if (ch < Character.MIN_HIGH_SURROGATE) {
                if (ch <= Unicode.MAX_C1_CTRL_CHAR && ch != Unicode.NEL) {
                    throw invalidCharacter(i, ch);
                }
            } else if (ch <= Character.MAX_HIGH_SURROGATE) {
                if (i + 1 < n && Character.isLowSurrogate(input.charAt(i + 1))) {
                    int cp = Character.toCodePoint(ch, input.charAt(i + 1));
                    if (Unicode.isNonCharacter(cp)) {
                        throw invalidCharacter(i, cp);
                    }
                    ++i;
                } else {
                    throw invalidCharacter(i, ch);
                }
            } else if (ch <= Character.MAX_LOW_SURROGATE || ch > '\ufffd'
                    || ('\ufdd0' <= ch && ch <= '\ufdef'))
            {
                throw invalidCharacter(i, ch);
            }
        }
    }

    /**
     * Builds the rejection for a character that is not valid in XML 1.0.
     *
     * @param offset the offset of the offending character in the input
     * @param cp the offending code point (or lone surrogate code unit)
     * @return the exception to throw
     */
    private static IllegalArgumentException invalidCharacter(int offset, int cp) {
        return new IllegalArgumentException(String.format(
            "XML comment input contains invalid XML character 0x%X at offset %d",
            cp, offset));
    }

    // Input:
    // <!-- foo -- bar -->
    // Possible Options:
    // <!-- foo &ndash; bar -->
    // <!-- foo == bar -->
    // <!-- foo __ bar -->
    // <!-- foo - - bar -->
    // <!-- foo \u2010\u2010 bar --> (Unicode Hyphen)
    // <!-- foo \u2013 bar --> (Unicode en-dash)
    // Note: HTML comments differ, in that they cannot start with: ">", "->".
    // On IE, "<!--[if ..." has special interpretation
    // [2] Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
    @Override
    protected int maxEncodedLength(int n) {
        return n;
    }

    @Override
    protected int firstEncodedOffset(String input, int off, int len) {
        final int n = off + len;
        for (int i = off; i < n; ++i) {
            char ch = input.charAt(i);
            if (ch <= Unicode.MAX_ASCII) {
                if (ch == '-') {
                    return i;
                } else if (ch < ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
                    return i;
//                } else {
//                    // valid
                }
            } else if (ch < Character.MIN_HIGH_SURROGATE) {
                if (ch <= Unicode.MAX_C1_CTRL_CHAR && ch != Unicode.NEL) {
                    return i;
//                } else {
//                    // valid
                }
            } else if (ch <= Character.MAX_HIGH_SURROGATE) {
                if (i + 1 < n && Character.isLowSurrogate(input.charAt(i + 1))) {
                    int cp = Character.toCodePoint(ch, input.charAt(i + 1));
                    if (Unicode.isNonCharacter(cp)) {
                        // noncharacter
                        return i;
                    }
                    ++i;
                } else {
                    return i;
                }
            } else if (ch <= Character.MAX_LOW_SURROGATE || ch > '\ufffd'
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
                if (ch == '-') {
                    if (j >= m) {
                        return overflow(input, i, output, j);
                    }
                    // Replacing every hyphen prevents a trusted trailing
                    // hyphen from combining with the start of this input.
                    out[j++] = HYPHEN_REPLACEMENT;
                } else if (ch > ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
                    if (j >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = ch;
                } else {
                    if (j >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = XMLEncoder.INVALID_CHARACTER_REPLACEMENT;
                }
            } else if (ch < Character.MIN_HIGH_SURROGATE) {
                if (j >= m) {
                    return overflow(input, i, output, j);
                }
                if (ch > Unicode.MAX_C1_CTRL_CHAR || ch == Unicode.NEL) {
                    out[j++] = ch;
                } else {
                    // C1 control code
                    out[j++] = XMLEncoder.INVALID_CHARACTER_REPLACEMENT;
                }
            } else if (ch <= Character.MAX_HIGH_SURROGATE) {
                if (i + 1 < n) {
                    if (Character.isLowSurrogate(in[i + 1])) {
                        int cp = Character.toCodePoint(ch, in[i + 1]);
                        if (Unicode.isNonCharacter(cp)) {
                            // noncharacter
                            if (j >= m) {
                                return overflow(input, i, output, j);
                            }
                            out[j++] = XMLEncoder.INVALID_CHARACTER_REPLACEMENT;
                            ++i;
                        } else {
                            if (j + 1 >= m) {
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
        return "XMLCommentEncoder";
    }
}
