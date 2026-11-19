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
 * sequence "]]>". This encoder fails closed: an input containing a literal
 * {@code "]]>"} sequence, an illegal XML 1.0 character (including NUL), a
 * malformed surrogate, or a Unicode noncharacter makes the encoding call throw
 * {@link EncodingException} instead of silently altering the value or emitting
 * another document. Legal inputs are represented with close/reopen sequences
 * for every {@code "]"} and {@code ">"}. That rule prevents any nonempty
 * encoded substring from completing a {@code "]]>"} delimiter supplied partly
 * by adjacent trusted literal text. Parsed character data of accepted inputs is
 * preserved, but a streaming XML consumer must handle multiple CDATA and
 * character-data events.
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

    /** The sequence that closes a CDATA section. */
    private static final char CLOSE_BRACKET = ']';

    /** The final character of the {@code "]]>"} terminator. */
    private static final char CLOSE_ANGLE = '>';

    /** Classification of one UTF-16 code unit for the CDATA context. */
    private enum Kind {
        /** Legal character data written through unchanged. */
        LITERAL,
        /** A {@code "]"} encoded with a close/reopen sequence. */
        BRACKET,
        /** A {@code ">"} encoded with a close/reopen sequence. */
        ANGLE,
        /** Leading unit of a legal supplementary-code-point pair. */
        HIGH_SURROGATE_PAIR,
        /** A code unit the CDATA context cannot represent. */
        ILLEGAL
    }

    /**
     * Builds the rejection exception for an ILLEGAL classification without
     * throwing it, so call sites control the throw and coverage remains
     * attributable to the branch that detected the bad code unit.
     *
     * @param ch the illegal code unit
     * @return an exception describing the violated rule
     */
    private static EncodingException illegalCharacterException(char ch) {
        if (ch < ' ') {
            return new EncodingException("CDATA encoding rejected input: "
                + "illegal XML 1.0 control character (U+"
                + String.format("%04X", (int) ch) + ")");
        }
        if (ch <= Unicode.MAX_C1_CTRL_CHAR) {
            return new EncodingException("CDATA encoding rejected input: "
                + "illegal XML 1.0 C1 control character (U+"
                + String.format("%04X", (int) ch) + ")");
        }
        if (ch <= Character.MAX_HIGH_SURROGATE) {
            return new EncodingException("CDATA encoding rejected input: "
                + "unpaired high surrogate (U+"
                + String.format("%04X", (int) ch) + ")");
        }
        if (ch <= Character.MAX_LOW_SURROGATE) {
            return new EncodingException("CDATA encoding rejected input: "
                + "low surrogate without high surrogate (U+"
                + String.format("%04X", (int) ch) + ")");
        }
        return new EncodingException("CDATA encoding rejected input: "
            + "Unicode noncharacter (U+"
            + String.format("%04X", (int) ch) + ")");
    }

    /**
     * Classifies the code unit at {@code index}. For a high surrogate the
     * caller supplies whether a following low surrogate exists via
     * {@code hasNext} and {@code nextIsLow}; a dangling high surrogate is
     * classified {@link Kind#ILLEGAL}. This is the single source of truth for
     * character validity, shared by the input validation, offset scan, and
     * encoding loop so every entry point fails closed identically.
     *
     * @param seq the input sequence
     * @param index index of the code unit to classify, relative to the start
     *              of {@code seq}
     * @param length length of {@code seq}
     * @return the classification of the code unit
     */
    private static Kind classify(CharSequence seq, int index, int length) {
        return classify(seq.charAt(index),
            index + 1 < length ? seq.charAt(index + 1) : '\u0000',
            index + 1 < length);
    }

    /**
     * Array-backed equivalent of {@link #classify(CharSequence, int, int)} for
     * the low-level buffer loop, where indices are absolute into the backing
     * array.
     *
     * @param data the backing input array
     * @param index absolute index of the code unit to classify
     * @param length absolute limit of the usable array region
     * @return the classification of the code unit
     */
    private static Kind classify(char[] data, int index, int length) {
        return classify(data[index],
            index + 1 < length ? data[index + 1] : '\u0000',
            index + 1 < length);
    }

    /**
     * Shared classification given the current unit and, when present, the unit
     * immediately following it.
     *
     * @param ch the current code unit
     * @param next the following code unit, ignored when {@code hasNext} is
     *             false
     * @param hasNext whether a following code unit exists
     * @return the classification of {@code ch}
     */
    private static Kind classify(char ch, char next, boolean hasNext) {
        if (ch <= Unicode.MAX_ASCII) {
            if (ch == CLOSE_BRACKET) {
                return Kind.BRACKET;
            }
            if (ch == CLOSE_ANGLE) {
                return Kind.ANGLE;
            }
            if (ch < ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
                return Kind.ILLEGAL;
            }
            return Kind.LITERAL;
        }
        if (ch < Character.MIN_HIGH_SURROGATE) {
            if (ch <= Unicode.MAX_C1_CTRL_CHAR && ch != Unicode.NEL
                    && ch != Unicode.DEL) {
                return Kind.ILLEGAL;
            }
            return Kind.LITERAL;
        }
        if (ch <= Character.MAX_HIGH_SURROGATE) {
            if (hasNext && Character.isLowSurrogate(next)) {
                return Unicode.isNonCharacter(Character.toCodePoint(ch, next))
                    ? Kind.ILLEGAL : Kind.HIGH_SURROGATE_PAIR;
            }
            return Kind.ILLEGAL;
        }
        if (ch <= Character.MAX_LOW_SURROGATE || ch > '\ufffd'
                || ('\ufdd0' <= ch && ch <= '\ufdef')) {
            return Kind.ILLEGAL;
        }
        return Kind.LITERAL;
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

    /**
     * Scans a complete logical input and fails closed on anything the CDATA
     * context cannot represent without escaping the section or changing the
     * parsed value: a literal {@code "]]>"} terminator, an illegal XML 1.0
     * character (including NUL), a malformed surrogate pair, or a Unicode
     * noncharacter. Called by the encoding facades before any output is
     * produced, so a rejection never leaves a partially written document.
     *
     * @param input the complete string supplied to an encoding facade
     * @throws EncodingException if {@code input} cannot be encoded safely
     */
    @Override
    void validateInput(String input) {
        final int n = input.length();
        EncodingException failure = null;
        for (int i = 0; i < n; ++i) {
            char ch = input.charAt(i);
            if (ch == CLOSE_BRACKET && i + 2 < n
                    && input.charAt(i + 1) == CLOSE_BRACKET
                    && input.charAt(i + 2) == CLOSE_ANGLE) {
                failure = new EncodingException("CDATA encoding rejected input: "
                    + "literal \"]]>\" terminator at offset " + i);
                break;
            }
            switch (classify(input, i, n)) {
                case HIGH_SURROGATE_PAIR:
                    ++i;
                    break;
                case ILLEGAL:
                    failure = illegalCharacterException(input.charAt(i));
                    break;
                default:
                    break;
            }
            if (failure != null) {
                break;
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    @Override
    protected int firstEncodedOffset(String input, int off, int len) {
        final int n = off + len;
        EncodingException failure = null;
        for (int i = off; i < n; ++i) {
            char ch = input.charAt(i);
            if (ch == CLOSE_BRACKET && i + 2 < n
                    && input.charAt(i + 1) == CLOSE_BRACKET
                    && input.charAt(i + 2) == CLOSE_ANGLE) {
                failure = new EncodingException("CDATA encoding rejected input: "
                    + "literal \"]]>\" terminator at offset " + i);
                break;
            }
            switch (classify(input, i, n)) {
                case BRACKET:
                case ANGLE:
                    return i;
                case HIGH_SURROGATE_PAIR:
                    ++i;
                    break;
                case ILLEGAL:
                    failure = illegalCharacterException(ch);
                    break;
                default:
                    break;
            }
            if (failure != null) {
                break;
            }
        }
        if (failure != null) {
            throw failure;
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
            if (ch == CLOSE_BRACKET && i + 2 < n
                    && in[i + 1] == CLOSE_BRACKET && in[i + 2] == CLOSE_ANGLE) {
                throw new EncodingException("CDATA encoding rejected input: "
                    + "literal \"]]>\" terminator at offset "
                    + (i - input.arrayOffset()));
            }
            switch (classify(in, i, n)) {
                case BRACKET:
                    if (m - j < RIGHT_BRACKET_ENCODED_LENGTH) {
                        return overflow(input, i, output, j);
                    }
                    System.arraycopy(RIGHT_BRACKET_ENCODED, 0, out, j,
                        RIGHT_BRACKET_ENCODED_LENGTH);
                    j += RIGHT_BRACKET_ENCODED_LENGTH;
                    break;
                case ANGLE:
                    if (m - j < GREATER_THAN_ENCODED_LENGTH) {
                        return overflow(input, i, output, j);
                    }
                    System.arraycopy(GREATER_THAN_ENCODED, 0, out, j,
                        GREATER_THAN_ENCODED_LENGTH);
                    j += GREATER_THAN_ENCODED_LENGTH;
                    break;
                case HIGH_SURROGATE_PAIR:
                    if (m - j < 2) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = ch;
                    out[j++] = in[i + 1];
                    ++i;
                    break;
                case ILLEGAL:
                    if (ch <= Character.MAX_HIGH_SURROGATE && i + 1 >= n
                            && !endOfInput) {
                        // Retain a trailing high surrogate until more input
                        // arrives or end-of-input proves it is unpaired.
                        return underflow(input, i, output, j);
                    }
                    throw illegalCharacterException(ch);
                case LITERAL:
                default:
                    if (j >= m) {
                        return overflow(input, i, output, j);
                    }
                    out[j++] = ch;
                    break;
            }
        }
        return underflow(input, i, output, j);
    }

    @Override
    public String toString() {
        return "CDATAEncoder";
    }
}
