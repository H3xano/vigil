package dev.vigil.inspector.data

import dev.vigil.inspector.R
import dev.vigil.inspector.ui.UiText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FeedCatalogTest {
    @Test
    fun everyBuiltinFeedHasATranslatedDescription() {
        for (f in FeedCatalog.builtin) {
            assertTrue(f.id, f.description.isNotEmpty())
            assertTrue(f.id, FeedCatalog.descriptionText(f) is UiText.Res)
        }
        val trackers = FeedCatalog.builtin.single { it.id == TrackerDatabase.FEED_ID }
        assertEquals(UiText.of(R.string.feeds_desc_trackers, TrackerDatabase.ATTRIBUTION), FeedCatalog.descriptionText(trackers))
    }

    @Test
    fun descriptiveNamesAreTranslatedProductNamesAreNot() {
        val byId = FeedCatalog.builtin.associateBy { it.id }
        assertEquals(UiText.of(R.string.feeds_name_native_samsung), FeedCatalog.nameText(byId.getValue("native-samsung")))
        assertEquals(UiText.Raw("abuse.ch URLhaus"), FeedCatalog.nameText(byId.getValue("urlhaus")))
        // A user's feed keeps its name even when its id looks like a built-in one.
        val custom = byId.getValue("native-samsung").copy(builtin = false, name = "Mine")
        assertEquals(UiText.Raw("Mine"), FeedCatalog.nameText(custom))
    }

    @Test
    fun customFeedsAndPacks() {
        fun custom(kind: String, description: String) =
            FeedEntity("custom-x", "X", "https://x", "malware", enabled = true, builtin = false, description = description, kind = kind)
        assertEquals(UiText.of(R.string.feeds_desc_custom), FeedCatalog.descriptionText(custom(FeedKinds.LIST, FeedCatalog.CUSTOM_DESCRIPTION)))
        assertEquals(UiText.of(R.string.feeds_desc_custom_ja4), FeedCatalog.descriptionText(custom(FeedKinds.JA4, FeedCatalog.CUSTOM_JA4_DESCRIPTION)))
        assertEquals(
            UiText.of(R.string.feeds_desc_taxii, "Indicators"),
            FeedCatalog.descriptionText(custom(FeedKinds.TAXII, FeedCatalog.taxiiDescription("Indicators"))),
        )
        // Any other stored text is shown as is; none at all shows nothing.
        assertEquals(UiText.Raw("test"), FeedCatalog.descriptionText(custom(FeedKinds.LIST, "test")))
        assertNull(FeedCatalog.descriptionText(custom(FeedKinds.LIST, "")))
        // MVT packs describe themselves (sources and licence from the index).
        val pack = FeedEntity("mvt-x", "Pack", "https://x", "malware", enabled = true, builtin = true, description = "Listed by MVT; licence: MIT.", kind = FeedKinds.SPYWARE)
        assertEquals(UiText.Raw("Listed by MVT; licence: MIT."), FeedCatalog.descriptionText(pack))
    }
}
