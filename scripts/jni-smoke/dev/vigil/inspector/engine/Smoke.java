package dev.vigil.inspector.engine;

import java.nio.file.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Drives the engine through JNI: start, feed load, upcalls, polling, stop. */
public final class Smoke {
    public static final AtomicInteger uidCalls = new AtomicInteger();
    public static final AtomicInteger protectCalls = new AtomicInteger();

    public static final class Bridge {
        public int ownerUid(int proto, byte[] src, int srcPort, byte[] dst, int dstPort) {
            uidCalls.incrementAndGet();
            if (src.length != 4 && src.length != 16) throw new IllegalStateException("bad address");
            return 10123;
        }
        public boolean protect(int fd) { protectCalls.incrementAndGet(); return fd > 0; }
    }

    static void check(String name, boolean ok) {
        System.out.println((ok ? "PASS " : "FAIL ") + "jni:" + name);
        if (!ok) failures++;
    }
    static int failures = 0;

    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        int fd = Integer.parseInt(args[1]);
        Path feed = Files.createTempFile("feed", ".txt");
        Files.writeString(feed, "0.0.0.0 blocked.vigil-test.example\n||c2.vigil-test.example^\n198.51.100.0/24\n");
        check("version", VigilNative.nativeVersion().matches("\\d+\\.\\d+\\.\\d+"));
        check("inspect-feed", VigilNative.nativeInspectFeedFile(feed.toString()).contains("\"domains\":2"));
        long h = VigilNative.nativeStart(fd, "{\"stats_interval_ms\":500,\"upstream_dns\":[\"127.0.0.1:9\"]}", new Bridge());
        check("start", h != 0);
        check("bad-config-rejected", !VigilNative.nativeUpdateConfig(h, "{not json"));
        check("config-update", VigilNative.nativeUpdateConfig(h, "{\"stats_interval_ms\":500,\"upstream_dns\":[\"127.0.0.1:9\"],\"sinkhole\":\"nxdomain\"}"));
        String summary = VigilNative.nativeLoadFeedFile(h, "smoke", "malware", feed.toString());
        check("load-feed", summary != null && summary.contains("\"ip_ranges\":1"));
        // Signal the namespace side to generate traffic, then collect events.
        Files.writeString(Path.of(args[2]), "ready");
        StringBuilder all = new StringBuilder();
        long deadline = System.currentTimeMillis() + 8000;
        while (System.currentTimeMillis() < deadline) {
            String batch = VigilNative.nativePollEvents(h, 500, 200);
            if (batch != null) all.append(batch).append('\n');
        }
        String ev = all.toString();
        check("dns-sinkhole-event", ev.contains("\"qname\":\"blocked.vigil-test.example\"") && ev.contains("\"rcode\":\"NXDOMAIN\""));
        check("uid-attributed", ev.contains("\"uid\":10123"));
        check("threat-alert", ev.contains("\"kind\":\"threat_domain\""));
        check("ip-block-flow", ev.contains("\"dst_ip\":\"198.51.100.7\"") && ev.contains("\"verdict\":\"block\""));
        check("stats-json", VigilNative.nativeStats(h).contains("\"dns_queries\""));
        check("uid-upcalls", uidCalls.get() >= 2);
        check("protect-upcalls", protectCalls.get() >= 1);
        check("remove-feed", VigilNative.nativeRemoveFeed(h, "smoke") && !VigilNative.nativeRemoveFeed(h, "smoke"));
        VigilNative.nativeStop(h);
        check("poll-after-stop-null-handle", VigilNative.nativePollEvents(0, 10, 0) == null);
        System.out.println("jni: " + (failures == 0 ? "all passed" : failures + " failed"));
        System.exit(failures == 0 ? 0 : 1);
    }
}
