package com.acme.report;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CollectionPerformance {
    public String join(List<String> parts) {
        if (parts.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (String part : parts) {
            out.append(part).append(",");
        }
        return out.toString();
    }

    public int totalFor(Map<String, Integer> counts) {
        int total = 0;
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            total += entry.getValue();
        }
        return total;
    }

    public boolean isBlank(String name) {
        return name == null || name.isEmpty();
    }

    public Deque<String> pending() {
        return new ArrayDeque<>();
    }

    public Map<String, Integer> tally(List<String> words) {
        Map<String, Integer> counts = new HashMap<>();
        for (String word : words) {
            counts.merge(word, 1, Integer::sum);
        }
        return counts;
    }

    public List<Integer> boxedIds(int[] ids) {
        List<Integer> boxed = new ArrayList<>();
        for (int id : ids) {
            boxed.add(Integer.valueOf(id));
        }
        return boxed;
    }
}
