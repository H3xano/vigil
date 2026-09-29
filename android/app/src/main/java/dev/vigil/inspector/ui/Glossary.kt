package dev.vigil.inspector.ui

import dev.vigil.inspector.R

/**
 * Short explanations for the technical terms shown in the UI, as string
 * resources (see res/values/strings_app.xml). Resolve an entry with
 * [asString] in Compose or [UiText.resolve].
 */
object Glossary {
    val SNI = UiText.of(R.string.glossary_sni)
    val NAME_SOURCE = UiText.of(R.string.glossary_name_source)
    /** [NAME_SOURCE] followed by [SNI], for the connection's "Name source" field. */
    val NAME_SOURCE_AND_SNI = paragraphs(NAME_SOURCE, SNI)
    val ALPN = UiText.of(R.string.glossary_alpn)
    val JA4 = UiText.of(R.string.glossary_ja4)
    val JA4_MATCH = UiText.of(R.string.glossary_ja4_match)
    val TAXII = UiText.of(R.string.glossary_taxii)
    val ECH = UiText.of(R.string.glossary_ech)
    val SINKHOLE = UiText.of(R.string.glossary_sinkhole)
    val SINKHOLED = UiText.of(R.string.glossary_sinkholed, SINKHOLE)
    val BEACONING = UiText.of(R.string.glossary_beaconing)
    val BEACONING_IN_CONNECTION = UiText.of(R.string.glossary_beaconing_in_connection)
    val EXFILTRATION = UiText.of(R.string.glossary_exfiltration)
    val C2 = UiText.of(R.string.glossary_c2)
    val ASN = UiText.of(R.string.glossary_asn)
    val NEW_ASN = UiText.of(R.string.glossary_new_asn, ASN)
    val VIA = UiText.of(R.string.glossary_via)
    val DNS_UPSTREAM = UiText.of(R.string.glossary_dns_upstream)
    val SPYWARE_PACKS = UiText.of(R.string.glossary_spyware_packs)
    val ECS = UiText.of(R.string.glossary_ecs)

    /** Two texts as separate paragraphs. */
    fun paragraphs(first: UiText, second: UiText): UiText = UiText.of(R.string.glossary_paragraphs, first, second)

    /** An introduction followed by a glossary text in the same paragraph. */
    fun sentences(first: UiText, second: UiText): UiText = UiText.of(R.string.glossary_sentences, first, second)
}
