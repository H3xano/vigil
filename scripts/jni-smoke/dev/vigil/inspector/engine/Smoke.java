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

    /** Sorted ids of all events of one type in a stream of JSON batches. */
    static java.util.List<Long> ids(String json, String type) {
        java.util.List<Long> out = new java.util.ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("\\{\"type\":\"" + type + "\",\"id\":(\\d+)").matcher(json);
        while (m.find()) out.add(Long.parseLong(m.group(1)));
        java.util.Collections.sort(out);
        return out;
    }

    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        int fd = Integer.parseInt(args[1]);
        Path feed = Files.createTempFile("feed", ".txt");
        Files.writeString(feed, "0.0.0.0 blocked.vigil-test.example\n||c2.vigil-test.example^\n198.51.100.0/24\n");
        check("version", VigilNative.nativeVersion().matches("\\d+\\.\\d+\\.\\d+"));
        check("inspect-feed", VigilNative.nativeInspectFeedFile(feed.toString()).contains("\"domains\":2"));
        long h = VigilNative.nativeStart(fd, "{\"stats_interval_ms\":500,\"upstream_dns\":[\"127.0.0.1:9\"]}", new Bridge());
        check("start", h != 0);
        check("invalid-config-start-refused", VigilNative.nativeStart(fd, "{\"mtu\":100}", new Bridge()) == 0);
        check("bad-config-rejected", !VigilNative.nativeUpdateConfig(h, "{not json"));
        check("invalid-config-rejected", !VigilNative.nativeUpdateConfig(h, "{\"upstream_dns\":[]}")
            && !VigilNative.nativeUpdateConfig(h, "{\"beacon\":{\"min_interval_s\":60,\"max_interval_s\":1}}"));
        check("config-update", VigilNative.nativeUpdateConfig(h, "{\"stats_interval_ms\":500,\"upstream_dns\":[\"127.0.0.1:9\"],\"sinkhole\":\"nxdomain\"}"));
        String summary = VigilNative.nativeLoadFeedFile(h, "smoke", "malware", feed.toString());
        check("load-feed", summary != null && summary.contains("\"ip_ranges\":1"));
        Path ja4 = Files.createTempFile("ja4", ".txt");
        Files.writeString(ja4, "# JA4\nt13d190900_9dc949149365_97f8aa674fd9  Sliver\nq13d0312h3_55b375c5d22e_*\nnot-a-ja4.example\n");
        check("inspect-ja4-feed", VigilNative.nativeInspectFeedFile(ja4.toString()).contains("\"ja4\":2"));
        String ja4Summary = VigilNative.nativeLoadFeedFile(h, "smoke-ja4", "ja4", ja4.toString());
        check("load-ja4-feed", ja4Summary != null && ja4Summary.contains("\"ja4\":2") && ja4Summary.contains("\"domains\":0")
            && ja4Summary.contains("\"rejected_lines\":1") && VigilNative.nativeRemoveFeed(h, "smoke-ja4"));
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

        // Shutdown keeps the handle: the queue drains, then polls return at once.
        check("shutdown", VigilNative.nativeShutdown(h));
        StringBuilder rest = new StringBuilder();
        String b;
        while ((b = VigilNative.nativePollEvents(h, 500, 0)) != null) rest.append(b).append('\n');
        check("shutdown-drains-stopped", rest.toString().contains("\"state\":\"stopped\""));
        long t0 = System.currentTimeMillis();
        check("poll-after-shutdown-empty", VigilNative.nativePollEvents(h, 10, 2000) == null);
        check("poll-after-shutdown-fast", System.currentTimeMillis() - t0 < 1000);
        String all2 = ev + rest;
        check("every-flow-ended", ids(all2, "flow").equals(ids(all2, "flow_end")));
        check("shutdown-twice", VigilNative.nativeShutdown(h));
        check("calls-after-shutdown-inert",
            !VigilNative.nativeUpdateConfig(h, "{}")
            && VigilNative.nativeStats(h) == null
            && VigilNative.nativeLoadFeedFile(h, "x", "malware", feed.toString()) == null
            && !VigilNative.nativeRemoveFeed(h, "x"));
        VigilNative.nativeStop(h);
        check("shutdown-null-handle", !VigilNative.nativeShutdown(0));

        // nativeStop without nativeShutdown still works.
        long h2 = VigilNative.nativeStart(fd, "{\"upstream_dns\":[\"127.0.0.1:9\"]}", new Bridge());
        check("restart", h2 != 0);
        VigilNative.nativeStop(h2);
        check("poll-after-stop-null-handle", VigilNative.nativePollEvents(0, 10, 0) == null);
        System.out.println("jni: " + (failures == 0 ? "all passed" : failures + " failed"));
        System.exit(failures == 0 ? 0 : 1);
    }
}
