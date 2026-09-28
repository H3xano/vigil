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

    static int u32(byte[] b, int o) {
        return (b[o] & 0xff) | (b[o + 1] & 0xff) << 8 | (b[o + 2] & 0xff) << 16 | (b[o + 3] & 0xff) << 24;
    }

    /** PCAPng: SHB, IDB with link type RAW (101), then at least one EPB; block lengths consistent. */
    static boolean checkPcapng(byte[] f) {
        if (f.length < 28 || u32(f, 0) != 0x0A0D0D0A || u32(f, 8) != 0x1A2B3C4D) return false;
        int pos = 0, epbs = 0, idbs = 0;
        while (pos + 12 <= f.length) {
            int type = u32(f, pos), len = u32(f, pos + 4);
            if (len < 12 || len % 4 != 0 || pos + len > f.length || u32(f, pos + len - 4) != len) return false;
            if (type == 1) { idbs++; if ((f[pos + 8] & 0xff | (f[pos + 9] & 0xff) << 8) != 101) return false; }
            if (type == 6) epbs++;
            pos += len;
        }
        return pos == f.length && idbs == 1 && epbs > 0;
    }

    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        int fd = Integer.parseInt(args[1]);
        Path feed = Files.createTempFile("feed", ".txt");
        Files.writeString(feed, "0.0.0.0 blocked.vigil-test.example\n||c2.vigil-test.example^\n198.51.100.0/24\n");
        check("version", VigilNative.nativeVersion().matches("\\d+\\.\\d+\\.\\d+"));
        check("inspect-feed", VigilNative.nativeInspectFeedFile(feed.toString()).contains("\"domains\":2"));
        String capture = ",\"capture\":{\"enabled\":true,\"buffer_bytes\":1048576}";
        long h = VigilNative.nativeStart(fd, "{\"stats_interval_ms\":500,\"upstream_dns\":[\"127.0.0.1:9\"]" + capture + "}", new Bridge());
        check("start", h != 0);
        check("invalid-config-start-refused", VigilNative.nativeStart(fd, "{\"mtu\":100}", new Bridge()) == 0);
        check("bad-config-rejected", !VigilNative.nativeUpdateConfig(h, "{not json"));
        check("invalid-config-rejected", !VigilNative.nativeUpdateConfig(h, "{\"upstream_dns\":[]}")
            && !VigilNative.nativeUpdateConfig(h, "{\"beacon\":{\"min_interval_s\":60,\"max_interval_s\":1}}"));
        // Per-app rules for the bridge's UID 10123: blocked on mobile data
        // (the device is on Wi-Fi below, so nothing is blocked by it) and one
        // name blocked for this app only.
        check("config-update", VigilNative.nativeUpdateConfig(h, "{\"stats_interval_ms\":500,\"upstream_dns\":[\"127.0.0.1:9\"],\"sinkhole\":\"nxdomain\","
            + "\"app_rules\":[{\"uid\":10123,\"block_cellular\":true}],"
            + "\"app_domain_rules\":[{\"uid\":10123,\"domain\":\"appblocked.vigil-test.example\",\"action\":\"block\"}]" + capture + "}"));
        check("device-state", VigilNative.nativeSetDeviceState(h, "{\"network\":\"wifi\",\"screen_on\":true,\"foreground_uids\":null}"));
        check("device-state-rejected", !VigilNative.nativeSetDeviceState(h, "{\"network\":\"satellite\"}")
            && !VigilNative.nativeSetDeviceState(h, "not json") && !VigilNative.nativeSetDeviceState(0, "{}"));
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
        check("app-domain-rule", ev.contains("\"reason\":\"app domain rule (appblocked.vigil-test.example)\""));
        check("condition-not-met-not-blocked", !ev.contains("app rule: "));
        check("stats-json", VigilNative.nativeStats(h).contains("\"dns_queries\""));
        check("stats-capture", VigilNative.nativeStats(h).contains("\"capture\":{\"enabled\":true"));
        Path pcap = Files.createTempFile("capture", ".pcapng");
        String sum = VigilNative.nativeExportPcap(h, "{}", pcap.toString());
        check("export-pcap", sum != null && !sum.contains("\"packets\":0,") && checkPcapng(Files.readAllBytes(pcap)));
        String byUid = VigilNative.nativeExportPcap(h, "{\"uids\":[10123]}", pcap.toString());
        byte[] uidFile = Files.readAllBytes(pcap);
        check("export-pcap-by-uid", byUid != null && !byUid.contains("\"packets\":0,")
            && new String(uidFile, java.nio.charset.StandardCharsets.ISO_8859_1).contains("uid=10123"));
        check("export-pcap-empty-filter-match", VigilNative.nativeExportPcap(h, "{\"flow_ids\":[999999]}", pcap.toString()).contains("\"packets\":0,"));
        check("export-pcap-bad-filter", VigilNative.nativeExportPcap(h, "{\"uids\":\"x\"}", pcap.toString()) == null
            && VigilNative.nativeExportPcap(0, "{}", pcap.toString()) == null
            && VigilNative.nativeExportPcap(h, "{}", "/nonexistent-dir/x.pcapng") == null);
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
            && !VigilNative.nativeRemoveFeed(h, "x")
            && !VigilNative.nativeSetDeviceState(h, "{}"));
        check("export-after-shutdown", VigilNative.nativeExportPcap(h, "{}", pcap.toString()) != null
            && checkPcapng(Files.readAllBytes(pcap)));
        Files.delete(pcap);
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
