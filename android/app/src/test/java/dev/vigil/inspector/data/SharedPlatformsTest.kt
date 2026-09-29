package dev.vigil.inspector.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SharedPlatformsTest {
    @Test
    fun wholePlatformsIncludingSubdomains() {
        for (h in listOf(
            "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "drive.google.com", "docs.google.com",
            "play.google.com", "cdn.discordapp.com", "dl.dropboxusercontent.com", "www.dropbox.com", "onedrive.live.com", "1drv.ms",
            "mega.nz", "pastebin.com", "t.me", "bit.ly", "GITHUB.COM", "github.com.",
        )) assertTrue(h, SharedPlatforms.isShared(h))
    }

    @Test
    fun hostingPlatformsOnlyAtTheApex() {
        for (h in listOf("herokuapp.com", "www.herokuapp.com", "github.io", "s3.amazonaws.com", "firebaseio.com")) {
            assertTrue(h, SharedPlatforms.isShared(h))
        }
        // A customer's own subdomain is a valid indicator.
        for (h in listOf("evil.herokuapp.com", "attacker.github.io", "edlnc255s2q.s3.amazonaws.com", "famisafe-b6807.firebaseio.com")) {
            assertFalse(h, SharedPlatforms.isShared(h))
        }
    }

    @Test
    fun lookalikesAreNotShared() {
        for (h in listOf("evilgithub.com", "github.com.evil.example", "notbit.ly", "google.com-login.example", "example.com")) {
            assertFalse(h, SharedPlatforms.isShared(h))
        }
    }

    @Test
    fun spywarePacksDropSharedSubdomains() {
        val groups = SpywareConverters.echapNetworkCsv(
            "type,indicator,app\ndomain,raw.githubusercontent.com,X\ndomain,drive.google.com,X\ndomain,c2.stalker.example,X\n" +
                "domain,x.herokuapp.com,X\n",
            "d",
        )
        assertTrue(groups.single().domains == listOf("c2.stalker.example", "x.herokuapp.com"))
    }
}
