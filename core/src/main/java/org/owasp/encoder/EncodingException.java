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
 * Thrown when an encoder cannot represent its input in the target context
 * without changing its meaning or weakening the context boundary. Encoders
 * fail closed instead of emitting replacement characters or an output that a
 * parser could interpret as a different document.
 *
 * <p>The CDATA context throws this exception when the input contains a
 * literal {@code "]]>"} sequence or a character that is not legal XML 1.0
 * character data, including the NUL character, other disallowed control
 * codes, unpaired UTF-16 surrogates, and Unicode noncharacters.</p>
 *
 * @author OWASP
 */
public class EncodingException extends RuntimeException {

    /** Serialization version. */
    private static final long serialVersionUID = 1L;

    /**
     * Constructs an encoding exception with a detail message.
     *
     * @param message the reason the input could not be encoded
     */
    public EncodingException(String message) {
        super(message);
    }

    /**
     * Constructs an encoding exception with a detail message and cause.
     *
     * @param message the reason the input could not be encoded
     * @param cause the underlying failure, or {@code null} if none
     */
    public EncodingException(String message, Throwable cause) {
        super(message, cause);
    }
}
