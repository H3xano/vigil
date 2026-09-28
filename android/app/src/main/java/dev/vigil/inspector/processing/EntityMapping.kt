package dev.vigil.inspector.processing

import dev.vigil.inspector.data.DnsEntity
import dev.vigil.inspector.data.FlowEntity
import dev.vigil.inspector.engine.DnsEvent
import dev.vigil.inspector.engine.FlowEvent

/** Engine events → Room rows. */
object EntityMapping {
    fun flow(e: FlowEvent, session: Long, pkg: String, background: Boolean?) = FlowEntity(
        session = session, engineId = e.id, ts = e.ts, proto = e.proto, uid = e.uid, pkg = pkg, src = e.src, dstIp = e.dstIp,
        dstPort = e.dstPort, domain = e.domain, domainSource = e.domainSource, appProto = e.appProto, alpn = e.alpn,
        tlsVersion = e.tlsVersion, ja4 = e.ja4, ech = e.ech, httpMethod = e.httpMethod, verdict = e.verdict ?: "allow",
        reason = e.reason, tags = e.tags.joinToString(","), background = background,
        ja4Feed = e.ja4Match?.feed, ja4Label = e.ja4Match?.label, via = e.via,
        asn = e.asn?.number?.takeIf { it > 0 }, asnName = e.asn?.name?.takeIf { it.isNotEmpty() && e.asn.number > 0 },
        asnCountry = e.asn?.country?.takeIf { e.asn.number > 0 },
    )

    fun dns(e: DnsEvent, pkg: String) = DnsEntity(
        ts = e.ts, uid = e.uid, pkg = pkg, qname = e.qname, qtype = e.qtype, rcode = e.rcode,
        answers = e.answers.joinToString(", "), verdict = e.verdict, reason = e.reason,
        latencyMs = e.latencyMs, server = e.server, transport = e.transport, upstream = e.upstream,
    )
}
