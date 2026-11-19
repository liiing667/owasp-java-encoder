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
import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Checks that {@link EncodedWriter} produces the same output as encoding the
 * whole text in one call, however the text is split across writes.  The splits
 * cut through sequences that encoders hold back for lookahead, at every fill
 * level of the writer's internal buffer near its capacity.
 */
public class EncodedWriterTest {

    /** Sequences that make at least one encoder wait for the next character. */
    private static final String[] PROBES = {
        "]]>", "]]]>>", "-->", "--->", "-a>", "<<a", "\"\"x", "\u2028 a", "\t0",
        "x\uD83D\uDE00y", "\uD83Dx", "</script>"
    };

    /** Written after each probe, so a context escape would expose markup. */
    private static final String TAIL = "<b>";

    @Test(timeout = 5000)
    public void cdataTerminatorSplitAcrossFullBufferStaysEncoded() throws IOException {
        StringWriter out = new StringWriter();
        EncodedWriter writer = new EncodedWriter(out, Encoders.CDATA);
        writer.write(repeat('a', 1008));
        writer.write("]]");
        writer.write("]]>>");
        writer.write("<script>");
        writer.close();
        assertEquals(Encode.forCDATA(repeat('a', 1008) + "]]]]>><script>"), out.toString());
    }

    @Test(timeout = 5000)
    public void xmlCommentTerminatorSplitAcrossFullBufferStaysEncoded() throws IOException {
        StringWriter out = new StringWriter();
        EncodedWriter writer = new EncodedWriter(out, Encoders.XML_COMMENT);
        writer.write(repeat('a', 1023));
        writer.write("-");
        writer.write("a><script>");
        writer.close();
        assertEquals(Encode.forXmlComment(repeat('a', 1023) + "-a><script>"), out.toString());
    }

    @Test(timeout = 5000)
    public void pendingLookaheadWithoutMoreInputDoesNotHang() throws IOException {
        StringWriter css = new StringWriter();
        EncodedWriter cssWriter = new EncodedWriter(css, Encoders.CSS_STRING);
        cssWriter.write('<');
        cssWriter.write('<');
        cssWriter.write("");
        cssWriter.close();
        assertEquals("\\3c\\3c", css.toString());

        StringWriter html = new StringWriter();
        EncodedWriter htmlWriter = new EncodedWriter(html, Encoders.HTML);
        htmlWriter.write("x\uD83D");
        htmlWriter.write("");
        htmlWriter.write("\uDE00");
        htmlWriter.close();
        assertEquals("x\uD83D\uDE00", html.toString());
    }

    @Test
    public void closeIsIdempotentAndClosedOperationsFail() throws IOException {
        StrictWriter out = new StrictWriter();
        final EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        writer.write("a\uD83D");
        writer.close();
        assertEquals("a ", out.toString());
        assertEquals(1, out.closeCount);

        writer.close();
        assertEquals(1, out.closeCount);
        assertIOException(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write('z');
            }
        });
        assertIOException(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write(new char[0], 0, 0);
            }
        });
        assertIOException(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write(new char[] {'z'});
            }
        });
        assertIOException(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write("z");
            }
        });
        assertIOException(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write("z", 0, 1);
            }
        });
        assertIOException(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.append('z');
            }
        });
        assertIOException(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.append("z");
            }
        });
        assertIOException(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.append("xyz", 1, 2);
            }
        });
        assertIOException(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.flush();
            }
        });
    }

    @Test
    public void closeStillClosesDelegateWhenFinalWriteFails() throws IOException {
        FailingWriter out = new FailingWriter(true, false);
        EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        writer.write('<');

        try {
            writer.close();
            fail("close should propagate the final write failure");
        } catch (IOException expected) {
            assertEquals("write failed", expected.getMessage());
        }
        assertEquals(1, out.closeCount);

        writer.close();
        assertEquals(1, out.closeCount);
    }

    @Test
    public void closePreservesSuppressedDelegateFailure() throws IOException {
        FailingWriter out = new FailingWriter(true, true);
        EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        writer.write('<');

        try {
            writer.close();
            fail("close should propagate the final write failure");
        } catch (IOException expected) {
            assertEquals("write failed", expected.getMessage());
            assertEquals(1, expected.getSuppressed().length);
            assertEquals("close failed", expected.getSuppressed()[0].getMessage());
        }
        assertEquals(1, out.closeCount);
    }

    @Test
    public void closePropagatesDelegateCloseFailureAndBecomesIdempotent()
            throws IOException {
        FailingWriter out = new FailingWriter(false, true);
        EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        writer.write('a');

        try {
            writer.close();
            fail("close should propagate the delegate close failure");
        } catch (IOException expected) {
            assertEquals("close failed", expected.getMessage());
            assertEquals(0, expected.getSuppressed().length);
        }
        assertEquals(1, out.closeCount);
        writer.close();
        assertEquals(1, out.closeCount);
    }

    @Test
    public void flushDoesNotFinalizePendingInput() throws IOException {
        StringWriter out = new StringWriter();
        EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        writer.write("x\uD83D");
        writer.flush();
        assertEquals("x", out.toString());
        writer.write("\uDE00");
        writer.close();
        assertEquals("x\uD83D\uDE00", out.toString());
    }

    @Test
    public void delegateWriteFailureIsPropagatedAndMarksWriterBroken() throws IOException {
        RecoverableWriter out = new RecoverableWriter();
        final EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        writer.write("safe");
        writer.flush();
        out.failWrites();

        try {
            writer.flush();
            fail("flush should propagate the delegate failure");
        } catch (IOException expected) {
            assertEquals("delegate write failed", expected.getMessage());
        }

        assertBroken(writer, "delegate write failed");
        writer.close();
        assertEquals(1, out.closeCount);
        // The accepted prefix is retained exactly; nothing failed is appended.
        assertEquals("safe", out.toString());

        writer.close();
        assertEquals(1, out.closeCount);
    }

    @Test
    public void interruptedStreamKeepsAcceptedPrefixWithoutDuplicatingBuffer()
            throws IOException {
        RecoverableWriter out = new RecoverableWriter();
        EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        // More than one output-buffer fill forces flushBufferToWriter while
        // input remains, so the internal buffer holds unsent encoded text.
        char[] input = new char[EncodedWriter.BUFFER_SIZE * 2 + 5];
        Arrays.fill(input, '<');
        out.failAfterAcceptedWrites(1);

        try {
            writer.write(input);
            fail("write should propagate the mid-stream delegate failure");
        } catch (IOException expected) {
            assertEquals("delegate write failed", expected.getMessage());
        }

        String acceptedAtFailure = out.toString();
        int writesAtFailure = out.writeCount;
        assertTrue(writesAtFailure > 0);

        // Every later operation must report the failure rather than look ok.
        assertBroken(writer, "delegate write failed");
        assertEquals(writesAtFailure, out.writeCount);
        assertEquals(acceptedAtFailure, out.toString());

        writer.close();
        assertEquals(writesAtFailure, out.writeCount);
        assertEquals(acceptedAtFailure, out.toString());
        // Accepted output is an exact prefix of the one-shot encoding: every
        // handed-off chunk is complete, in order and never written twice.
        String fullEncoding = Encode.forHtml(new String(input));
        assertEquals(fullEncoding.substring(0, acceptedAtFailure.length()), acceptedAtFailure);
        assertTrue(acceptedAtFailure.length() < fullEncoding.length());
    }

    @Test
    public void recoveredDelegateResumesEncodingThroughAFreshWriter()
            throws IOException {
        RecoverableWriter out = new RecoverableWriter();
        EncodedWriter first = new EncodedWriter(out, Encoders.HTML);
        first.write("a<");
        first.flush();
        out.failWrites();
        try {
            first.flush();
            fail("flush should propagate the delegate failure");
        } catch (IOException expected) {
            assertEquals("delegate write failed", expected.getMessage());
        }
        first.close();
        String prefix = out.toString();
        assertEquals("a&lt;", prefix);

        // The fixed delegate recovers; a new writer resumes the stream and
        // the concatenation equals encoding the whole logical text at once.
        out.recover();
        EncodedWriter second = new EncodedWriter(out, Encoders.HTML);
        second.write("b>c");
        second.close();

        assertEquals(Encode.forHtml("a<b>c"), out.toString());
        assertEquals(2, out.closeCount);
    }

    @Test
    public void failedBufferDrainDuringFlushIsPropagatedAndMarksWriterBroken()
            throws IOException {
        RecoverableWriter out = new RecoverableWriter();
        final EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        // Keep the encoded output inside the EncodedWriter buffer until flush.
        writer.write("<a>");
        assertEquals(0, out.writeCount);
        // flush() drains the internal buffer through a delegated write before
        // calling flush(); failing there models a broken underlying stream.
        out.failWrites();

        try {
            writer.flush();
            fail("flush should propagate the delegate write failure");
        } catch (IOException expected) {
            assertEquals("delegate write failed", expected.getMessage());
        }

        assertBroken(writer, "delegate write failed");

        out.recover();
        assertBroken(writer, "delegate write failed");
        writer.close();
        // The failed flush never reached the delegate, so it received nothing.
        assertEquals("", out.toString());

        // A replacement writer over the recovered delegate still produces the
        // complete encoding, streamed in order.
        out.recover();
        EncodedWriter replacement = new EncodedWriter(out, Encoders.HTML);
        replacement.write("<a>");
        replacement.close();
        assertEquals(Encode.forHtml("<a>"), out.toString());
    }

    @Test
    public void pureDelegateFlushFailureIsPropagatedAndMarksWriterBroken()
            throws IOException {
        RecoverableWriter out = new RecoverableWriter();
        final EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        // An empty internal buffer means flush() reaches the delegate flush
        // without any preceding write.
        writer.flush();
        assertEquals(1, out.flushCount);
        out.failFlushes();

        try {
            writer.flush();
            fail("flush should propagate the delegate flush failure");
        } catch (IOException expected) {
            assertEquals("delegate flush failed", expected.getMessage());
        }

        assertBroken(writer, "delegate flush failed");
        writer.close();
        assertEquals("", out.toString());
    }

    @Test(timeout = 30000)
    public void concurrentWritesStaySynchronizedAndFailureIsVisibleToEveryCaller()
            throws Exception {
        final RecoverableWriter out = new RecoverableWriter();
        final EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        int threads = 4;
        int chunksPerThread = 200;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> results = new ArrayList<Future<?>>();
            for (int t = 0; t < threads; ++t) {
                final int index = t;
                results.add(pool.submit(new Runnable() {
                    @Override
                    public void run() {
                        awaitQuietly(start);
                        for (int i = 0; i < chunksPerThread; ++i) {
                            try {
                                writer.write("t" + index + "<");
                            } catch (IOException e) {
                                throw new AssertionError("healthy stream failed", e);
                            }
                        }
                    }
                }));
            }
            start.countDown();
            for (Future<?> result : results) {
                result.get(30, TimeUnit.SECONDS);
            }
            writer.close();

            // Each delegated write is one encoded chunk, so every chunk stays
            // intact and is accepted exactly once; thread scheduling decides
            // the chunk order, but no content may be lost or duplicated.
            int totalInputs = threads * chunksPerThread;
            String accepted = out.toString();
            assertEquals(totalInputs * ("t".length() + 1 + "&lt;".length()),
                accepted.length());
            for (int t = 0; t < threads; ++t) {
                String expectedChunk = "t" + t + "&lt;";
                int occurrences = 0;
                int index = 0;
                while ((index = accepted.indexOf(expectedChunk, index)) != -1) {
                    ++occurrences;
                    index += expectedChunk.length();
                }
                assertEquals(chunksPerThread, occurrences);
            }
        } finally {
            pool.shutdownNow();
        }

        // A later failure on a reused writer must be visible to all callers.
        RecoverableWriter failing = new RecoverableWriter();
        final EncodedWriter broken = new EncodedWriter(failing, Encoders.HTML);
        broken.write("ok");
        broken.flush();
        failing.failWrites();
        try {
            broken.flush();
            fail("flush should propagate the delegate failure");
        } catch (IOException expected) {
            assertEquals("delegate write failed", expected.getMessage());
        }
        ExecutorService failurePool = Executors.newFixedThreadPool(threads);
        try {
            final AtomicInteger failures = new AtomicInteger();
            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> results = new ArrayList<Future<?>>();
            for (int t = 0; t < threads; ++t) {
                results.add(failurePool.submit(new Runnable() {
                    @Override
                    public void run() {
                        awaitQuietly(start);
                        try {
                            broken.write("<");
                        } catch (IOException e) {
                            failures.incrementAndGet();
                        }
                    }
                }));
            }
            start.countDown();
            for (Future<?> result : results) {
                result.get(30, TimeUnit.SECONDS);
            }
            assertEquals(threads, failures.get());
            broken.close();
            assertEquals("ok", failing.toString());
        } finally {
            failurePool.shutdownNow();
        }
    }

    private static void assertBroken(EncodedWriter writer, String causeMessage) {
        try {
            writer.write("z");
            fail("write on a broken writer should fail");
        } catch (IOException expected) {
            assertSameCause(causeMessage, expected);
        }
        try {
            writer.flush();
            fail("flush on a broken writer should fail");
        } catch (IOException expected) {
            assertSameCause(causeMessage, expected);
        }
    }

    private static void assertSameCause(String causeMessage, IOException failure) {
        assertEquals("Writer is broken by an earlier I/O failure", failure.getMessage());
        Throwable cause = failure.getCause();
        assertTrue("expected wrapped cause", cause instanceof IOException);
        assertEquals(causeMessage, cause.getMessage());
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }

    @Test
    public void invalidWriteRangesThrowIndexOutOfBoundsException() throws IOException {
        StringWriter out = new StringWriter();
        final EncodedWriter writer = new EncodedWriter(out, Encoders.HTML);
        final char[] chars = {'a'};

        try {
            writer.write((char[]) null, 0, 0);
            fail("expected NullPointerException");
        } catch (NullPointerException expected) {
            // Expected.
        }
        assertIndexOutOfBounds(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write(chars, -1, 1);
            }
        });
        assertIndexOutOfBounds(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write(chars, 0, -1);
            }
        });
        assertIndexOutOfBounds(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write(chars, 1, 1);
            }
        });
        assertIndexOutOfBounds(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write(chars, Integer.MAX_VALUE, 1);
            }
        });
        assertIndexOutOfBounds(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write(chars, 1, Integer.MAX_VALUE);
            }
        });
        assertIndexOutOfBounds(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write(chars, Integer.MAX_VALUE, Integer.MAX_VALUE);
            }
        });
        assertIndexOutOfBounds(new IOAction() {
            @Override
            public void run() throws IOException {
                writer.write(chars, chars.length + 1, 0);
            }
        });

        writer.write(chars, chars.length, 0);
        writer.close();
        assertEquals("", out.toString());
    }

    @Test(timeout = 60000)
    public void splitWritesMatchSingleCallEncoding() throws Exception {
        List<String> names = MaxEncodedLengthTest.contextNames();
        assertTrue(names.size() > 1);
        int checked = 0;
        for (String name : names) {
            Encoder encoder = Encoders.forName(name);
            for (String probe : PROBES) {
                for (int fill = EncodedWriter.BUFFER_SIZE - 20; fill <= EncodedWriter.BUFFER_SIZE; ++fill) {
                    for (List<String> writes : splits(probe)) {
                        assertSameAsSingleCall(name, encoder, repeat('a', fill), writes);
                        ++checked;
                    }
                }
            }
        }
        assertTrue(checked > 10000);
    }

    private static void assertSameAsSingleCall(String name, Encoder encoder, String filler, List<String> writes)
            throws IOException {
        StringBuilder text = new StringBuilder(filler);
        StringWriter out = new StringWriter();
        EncodedWriter writer = new EncodedWriter(out, encoder);
        writer.write(filler);
        for (String write : writes) {
            writer.write(write);
            text.append(write);
        }
        writer.write(TAIL);
        text.append(TAIL);
        writer.close();

        String expected = encodeInOneCall(encoder, text);
        if (!expected.equals(out.toString())) {
            fail(name + " with " + filler.length() + " filler characters, then writes "
                + MaxEncodedLengthTest.escape(writes.toString()) + ": expected ..."
                + MaxEncodedLengthTest.escape(tail(expected)) + " but was ..."
                + MaxEncodedLengthTest.escape(tail(out.toString())));
        }
    }

    /**
     * Returns ways to split {@code probe} into writes: at every position
     * (including empty writes at either end), one character per write, and one
     * character per write with an empty write after each.
     */
    private static List<List<String>> splits(String probe) {
        List<List<String>> splits = new ArrayList<List<String>>();
        for (int i = 0; i <= probe.length(); ++i) {
            splits.add(Arrays.asList(probe.substring(0, i), probe.substring(i)));
        }
        List<String> single = new ArrayList<String>();
        List<String> singleWithEmpty = new ArrayList<String>();
        for (int i = 0; i < probe.length(); ++i) {
            single.add(probe.substring(i, i + 1));
            singleWithEmpty.add(probe.substring(i, i + 1));
            singleWithEmpty.add("");
        }
        splits.add(single);
        splits.add(singleWithEmpty);
        return splits;
    }

    private static String encodeInOneCall(Encoder encoder, CharSequence text) {
        CharBuffer in = CharBuffer.wrap(text.toString().toCharArray());
        CharBuffer out = CharBuffer.allocate(text.length() * 32);
        assertTrue(encoder.encode(in, out, true).isUnderflow());
        return new String(out.array(), 0, out.position());
    }

    private static String tail(String s) {
        return s.substring(Math.max(0, s.length() - 40));
    }

    private static String repeat(char ch, int n) {
        char[] chars = new char[n];
        Arrays.fill(chars, ch);
        return new String(chars);
    }

    private static void assertIOException(IOAction action) {
        try {
            action.run();
            fail("expected IOException");
        } catch (IOException expected) {
            // Expected.
        }
    }

    private static void assertIndexOutOfBounds(IOAction action) throws IOException {
        try {
            action.run();
            fail("expected IndexOutOfBoundsException");
        } catch (IndexOutOfBoundsException expected) {
            // Expected.
        }
    }

    private interface IOAction {
        void run() throws IOException;
    }

    private static final class StrictWriter extends Writer {

        private final StringBuilder output = new StringBuilder();
        private boolean closed;
        private int closeCount;

        @Override
        public void write(char[] cbuf, int off, int len) throws IOException {
            ensureOpen();
            output.append(cbuf, off, len);
        }

        @Override
        public void flush() throws IOException {
            ensureOpen();
        }

        @Override
        public void close() {
            closed = true;
            ++closeCount;
        }

        @Override
        public String toString() {
            return output.toString();
        }

        private void ensureOpen() throws IOException {
            if (closed) {
                throw new IOException("strict writer closed");
            }
        }
    }

    private static final class FailingWriter extends Writer {

        private final boolean failWrite;
        private final boolean failClose;
        private int closeCount;

        FailingWriter(boolean failWrite, boolean failClose) {
            this.failWrite = failWrite;
            this.failClose = failClose;
        }

        @Override
        public void write(char[] cbuf, int off, int len) throws IOException {
            if (failWrite) {
                throw new IOException("write failed");
            }
        }

        @Override
        public void flush() {
            // Nothing to do.
        }

        @Override
        public void close() throws IOException {
            ++closeCount;
            if (failClose) {
                throw new IOException("close failed");
            }
        }
    }

    /**
     * A fixed in-memory delegate that models a stream which fails mid-use and
     * can later be recovered. It records every chunk the EncodedWriter actually
     * handed off, together with write, flush and close counts, so tests can
     * prove that interrupted output is neither duplicated nor partially
     * replayed and that streaming resumes correctly after {@link #recover()}.
     */
    private static final class RecoverableWriter extends Writer {

        private final StringBuilder output = new StringBuilder();
        private volatile boolean writesFailing;
        private volatile boolean flushesFailing;
        private volatile int acceptedWritesBeforeFailure = Integer.MAX_VALUE;
        private boolean closed;
        private int writeCount;
        private int flushCount;
        private int closeCount;

        void failWrites() {
            writesFailing = true;
        }

        void failFlushes() {
            flushesFailing = true;
        }

        void failAfterAcceptedWrites(int acceptedWrites) {
            acceptedWritesBeforeFailure = acceptedWrites;
        }

        void recover() {
            writesFailing = false;
            flushesFailing = false;
            acceptedWritesBeforeFailure = Integer.MAX_VALUE;
            closed = false;
        }

        @Override
        public void write(char[] cbuf, int off, int len) throws IOException {
            if (closed) {
                throw new IOException("delegate is closed");
            }
            if (writesFailing || writeCount >= acceptedWritesBeforeFailure) {
                throw new IOException("delegate write failed");
            }
            output.append(cbuf, off, len);
            ++writeCount;
        }

        @Override
        public void flush() throws IOException {
            ++flushCount;
            if (flushesFailing) {
                throw new IOException("delegate flush failed");
            }
            if (closed) {
                throw new IOException("delegate is closed");
            }
        }

        @Override
        public void close() {
            closed = true;
            ++closeCount;
        }

        @Override
        public String toString() {
            return output.toString();
        }
    }
}
