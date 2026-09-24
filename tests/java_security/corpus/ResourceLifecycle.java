package com.acme.batch;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;

public class ResourceLifecycle {
    private static final Logger log = LoggerFactory.getLogger(ResourceLifecycle.class);
    private final DataSource dataSource;

    public String readManifest(Path manifest) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(manifest)) {
            return reader.readLine();
        }
    }

    public int archiveOrders(String status) throws SQLException {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement("UPDATE orders SET archived = true WHERE status = ?")) {
            ps.setString(1, status);
            return ps.executeUpdate();
        }
    }

    public void runBatch(List<Runnable> jobs) throws InterruptedException {
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            for (Runnable job : jobs) {
                pool.submit(job);
            }
        } finally {
            pool.shutdown();
            pool.awaitTermination(30, TimeUnit.SECONDS);
        }
    }

    public Config loadConfig(Path path) {
        try {
            return parse(Files.readString(path));
        } catch (ConfigParseException e) {
            log.warn("using defaults: {}", e.getMessage());
            return Config.defaults();
        } catch (IOException e) {
            throw new ConfigLoadException("could not read " + path, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ConfigLoadException("interrupted while loading " + path, e);
        }
    }

    private Config parse(String text) throws ConfigParseException {
        if (text.isEmpty()) {
            throw new ConfigParseException("empty config");
        }
        return Config.fromJson(text);
    }
}
