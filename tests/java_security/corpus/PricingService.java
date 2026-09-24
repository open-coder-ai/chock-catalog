package com.acme.pricing;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Correct forms of the constructs the bugs pack refuses -- none of it should ever fire here. */
public class PricingService {

    public boolean isAdminTier(String tier) {
        return "admin".equals(tier);
    }

    public boolean sameTier(String a, String b) {
        return Objects.equals(a, b);
    }

    public BigDecimal parsePrice(String literal) {
        return new BigDecimal(literal);
    }

    public BigDecimal roundedFromDouble(double rate) {
        return BigDecimal.valueOf(rate);
    }

    public boolean isMissing(double value) {
        return Double.isNaN(value);
    }

    public String normalize(String s) {
        return s.trim().toUpperCase();
    }

    public LocalDate nextBillingDate(LocalDate today) {
        return today.plusDays(30);
    }

    public double averageRatio(int a, int b) {
        return (double) a / b;
    }

    public String describe(int[] scores) {
        return Arrays.toString(scores);
    }

    public String describeAll(List<String> names) {
        return names.toString();
    }

    public void startWorker(Runnable task) {
        Thread worker = new Thread(task);
        worker.start();
    }

    public int bucketFor(Object key) {
        return Math.floorMod(key.hashCode(), 16);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof PricingService;
    }

    @Override
    public int hashCode() {
        return PricingService.class.hashCode();
    }
}
