package com.acme.jobs;

import java.time.format.DateTimeFormatter;
import java.util.concurrent.locks.ReentrantLock;

/** Correct forms of the constructs the concurrency pack refuses -- none of it should ever fire here. */
public class JobScheduler {

    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ISO_INSTANT;

    private final Object lock = new Object();
    private final ReentrantLock queueLock = new ReentrantLock();
    private volatile Helper helper;

    Helper helper() {
        if (helper == null) {
            synchronized (lock) {
                if (helper == null) {
                    helper = new Helper();
                }
            }
        }
        return helper;
    }

    void runBatch() {
        synchronized (lock) {
            drainQueue();
        }
    }

    void awaitReady() throws InterruptedException {
        synchronized (lock) {
            while (!ready()) {
                lock.wait();
            }
        }
    }

    void backOff() throws InterruptedException {
        while (shouldRetry()) {
            Thread.sleep(50);
        }
    }

    void finish() {
        synchronized (lock) {
            markDone();
            lock.notifyAll();
        }
    }

    private void drainQueue() {
        // real work
    }

    private boolean ready() {
        return true;
    }

    private boolean shouldRetry() {
        return false;
    }

    private void markDone() {
        // real work
    }

    static final class Helper {
    }
}
