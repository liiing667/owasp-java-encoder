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
import java.io.StringWriter;
import java.io.Writer;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Checks that the Writer paths keep their state, their exception
 * propagation and their final output consistent: a failing writer makes
 * calls fail (never silently succeed), a recovered writer receives the
 * retained output exactly once, concurrent encodings to a shared writer
 * are not torn into interleaved halves, and ordinary streaming encoding
 * is unchanged.
 */
public class WriterConsistencyTest {

    /**
     * A writer fixture that can be broken and repaired to demonstrate
     * interruption and recovery.  While broken, every operation fails;
     * nothing is written and nothing is dropped silently.
     */
    private static final class InterruptibleWriter extends Writer {
        private final StringBuilder output = new StringBuilder();
        private boolean broken;
        private int closeCount;

        void breakdown() {
            broken = true;
        }

        void recover() {
            broken = false;
        }

        String written() {
            return output.toString();
        }

        @Override
        public void write(char[] cbuf, int off, int len) throws IOException {
            if (broken) {
                throw new IOException("interrupted");
            }
            output.append(cbuf, off, len);
        }

        @Override
        public void write(String str) throws IOException {
            if (broken) {
                throw new IOException("interrupted");
            }
            output.append(str);
        }

        @Override
        public void flush() throws IOException {
            if (broken) {
                throw new IOException("interrupted");
            }
        }

        @Override
        public void close() throws IOException {
            ++closeCount;
            if (broken) {
                throw new IOException("interrupted");
            }
        }
    }

    private static String repeat(char ch, int n) {
        char[] chars = new char[n];
        Arrays.fill(chars, ch);
        return new String(chars);
    }

    @Test
    public void facadeFailurePropagatesAndNothingIsWritten() {
        InterruptibleWriter out = new InterruptibleWriter();
        out.breakdown();
        try {
            Encode.forHtml(out, "<script>");
            fail("a broken writer must not report success");
        } catch (IOException expected) {
            assertEquals("interrupted", expected.getMessage());
        }
        assertEquals("a failed call leaves no partial output", "", out.written());
    }

    @Test
    public void facadeFailureMidStreamPropagatesAndRecoveryIsComplete() throws IOException {
        // Enough input to force several batched writes; the writer is
        // broken from the start so the failure happens on the first
        // batch, then the recovered writer accepts the full encoding.
        InterruptibleWriter out = new InterruptibleWriter();
        String input = repeat('<', 4 * Encode.Buffer.INPUT_BUFFER_SIZE);
        out.breakdown();
        try {
            Encode.forHtml(out, input);
            fail("a broken writer must not report success");
        } catch (IOException expected) {
            assertEquals("interrupted", expected.getMessage());
        }
        out.recover();
        Encode.forHtml(out, input);
        assertEquals(Encode.forHtml(input), out.written());
    }

    @Test
    public void facadeRecoveryProducesIdenticalOutput() throws IOException {
        InterruptibleWriter out = new InterruptibleWriter();
        out.breakdown();
        try {
            Encode.forHtml(out, "<script>");
            fail("expected IOException");
        } catch (IOException expected) {
            // Expected.
        }
        out.recover();
        Encode.forHtml(out, "<script>");
        assertEquals(Encode.forHtml("<script>"), out.written());
    }

    @Test
    public void encodedWriterFlushInterruptionAndRecovery() throws IOException {
        InterruptibleWriter out = new InterruptibleWriter();
        EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        writer.write("a<b\uD83D\uDE00");

        out.breakdown();
        try {
            writer.flush();
            fail("flush should propagate the delegate failure");
        } catch (IOException expected) {
            assertEquals("interrupted", expected.getMessage());
        }
        assertEquals("nothing written while interrupted", "", out.written());

        out.recover();
        writer.flush();
        assertEquals(Encode.forHtml("a<b\uD83D\uDE00"), out.written());

        writer.close();
        assertEquals("retained output is written exactly once",
            Encode.forHtml("a<b\uD83D\uDE00"), out.written());
        assertEquals(1, out.closeCount);
    }

    @Test
    public void encodedWriterWriteInterruptionAndRecovery() throws IOException {
        InterruptibleWriter out = new InterruptibleWriter();
        EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        // Large enough to overflow the internal buffer, so the delegate
        // write (and its failure) happens inside write().
        String input = repeat('<', 3 * EncodedWriter.BUFFER_SIZE);

        out.breakdown();
        try {
            writer.write(input);
            fail("write should propagate the delegate failure");
        } catch (IOException expected) {
            assertEquals("interrupted", expected.getMessage());
        }

        out.recover();
        // The input consumed before the failure stays buffered; flushing
        // emits it exactly once, and the result is a clean prefix of the
        // complete encoding--never a half-encoded or duplicated segment.
        writer.flush();
        writer.close();
        String recovered = out.written();
        String complete = Encode.forHtml(input);
        assertTrue("recovered output must not be empty", recovered.length() > 0);
        assertTrue("recovered output is a prefix of the complete encoding",
            complete.startsWith(recovered));
        assertEquals(1, out.closeCount);
    }

    @Test(timeout = 30000)
    public void concurrentFacadeEncodingsStayContiguous() throws Exception {
        // Two logical encodings to one shared writer.  Each is large
        // enough to span many internal batches, so without coordination
        // the two outputs interleave into half-encoded segments.
        final String first = repeat('<', 20000);
        final String second = repeat('>', 20000);
        final String encodedFirst = Encode.forHtml(first);
        final String encodedSecond = Encode.forHtml(second);

        for (int trial = 0; trial < 10; ++trial) {
            final StringWriter out = new StringWriter();
            final AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
            Thread a = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Encode.forHtml(out, first);
                    } catch (Throwable t) {
                        failure.set(t);
                    }
                }
            });
            Thread b = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Encode.forHtml(out, second);
                    } catch (Throwable t) {
                        failure.set(t);
                    }
                }
            });
            a.start();
            b.start();
            a.join();
            b.join();
            if (failure.get() != null) {
                throw new AssertionError("unexpected failure", failure.get());
            }
            String actual = out.toString();
            assertTrue("each logical encoding must stay contiguous",
                actual.equals(encodedFirst + encodedSecond)
                    || actual.equals(encodedSecond + encodedFirst));
        }
    }

    @Test(timeout = 30000)
    public void facadeCoordinatesWithEncodedWriterOnSharedWriter() throws Exception {
        final String viaFacade = repeat('<', 20000);
        final String viaStream = repeat('>', 2000);
        final String encodedFacade = Encode.forHtml(viaFacade);
        final String encodedStream = Encode.forHtml(viaStream);

        for (int trial = 0; trial < 10; ++trial) {
            final StringWriter out = new StringWriter();
            final EncodedWriter stream = new EncodedWriter(out, Encoders.HTML);
            final AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
            Thread a = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Encode.forHtml(out, viaFacade);
                    } catch (Throwable t) {
                        failure.set(t);
                    }
                }
            });
            Thread b = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        for (int i = 0; i < viaStream.length(); i += 100) {
                            stream.write(viaStream, i, Math.min(100, viaStream.length() - i));
                        }
                        stream.close();
                    } catch (Throwable t) {
                        failure.set(t);
                    }
                }
            });
            a.start();
            b.start();
            a.join();
            b.join();
            if (failure.get() != null) {
                throw new AssertionError("unexpected failure", failure.get());
            }
            String actual = out.toString();
            // The facade encoding is one contiguous block; the streamed
            // encoding may appear before and/or after it, but never
            // interleaved within the facade block.
            int at = actual.indexOf(encodedFacade);
            assertTrue("facade encoding must stay contiguous", at >= 0);
            assertEquals(encodedStream,
                actual.substring(0, at) + actual.substring(at + encodedFacade.length()));
        }
    }

    @Test
    public void streamingSplitWritesStillMatchSingleCall() throws IOException {
        // Legal streaming encoding is unchanged: input split at arbitrary
        // points, including through a surrogate pair, encodes identically
        // to a single call.
        StringWriter out = new StringWriter();
        EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        writer.write("a<");
        writer.write("b\uD83D");
        writer.write("\uDE00&");
        writer.close();
        assertEquals(Encode.forHtml("a<b\uD83D\uDE00&"), out.toString());
    }
}
