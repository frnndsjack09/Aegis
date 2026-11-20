package com.aegis.scanner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class PhoneHealthTest {

    private static final long DAY = 24L * 3600 * 1000;
    // 20 Nov 2026, 00:00 UTC
    private static final long NOW = 1795132800000L;

    private static PhoneHealth.Inputs healthy() {
        PhoneHealth.Inputs in = new PhoneHealth.Inputs();
        in.now = NOW;
        in.uptimeMs = DAY / 2;
        in.securityPatch = "2026-10-01";
        in.privateDnsKnown = true;
        in.privateDnsName = "dns.adguard-dns.com";
        in.freeBytes = 150_000_000_000L;
        in.totalBytes = 230_000_000_000L;
        in.batteryTempTenths = 330;
        in.batteryHealth = PhoneHealth.HEALTH_GOOD;
        in.memAvail = 5_000_000_000L;
        in.memTotal = 11_000_000_000L;
        in.bigApps = new ArrayList<>();
        return in;
    }

    private static Finding find(List<Finding> list, String category) {
        for (Finding f : list) if (f.category.equals(category)) return f;
        return null;
    }

    @Test
    public void healthyPhoneIsAllGreen() {
        for (Finding f : PhoneHealth.judge(healthy())) assertEquals(f.title, Finding.Level.GREEN, f.level);
    }

    @Test
    public void flagsOldPatchLongUptimeAndHeat() {
        PhoneHealth.Inputs in = healthy();
        in.securityPatch = "2026-05-01";       // ~6.5 months
        in.uptimeMs = 9 * DAY;
        in.batteryTempTenths = 465;
        List<Finding> out = PhoneHealth.judge(in);
        assertEquals(Finding.Level.YELLOW, find(out, "Updates").level);
        assertEquals(Finding.Level.YELLOW, find(out, "Restart").level);
        assertEquals(Finding.Level.YELLOW, find(out, "Battery").level);
        assertEquals(Finding.Level.YELLOW, out.get(0).level); // problems sort first
    }

    @Test
    public void suggestsPrivateDnsOnlyWhenOff() {
        PhoneHealth.Inputs in = healthy();
        in.privateDnsName = null;
        Finding f = find(PhoneHealth.judge(in), "Safe browsing");
        assertEquals(Finding.Level.INFO, f.level);
        assertEquals(Finding.ActionType.COPY, f.actions.get(0).type);
        assertEquals("dns.adguard-dns.com", f.actions.get(0).target);
    }

    @Test
    public void nearlyFullStorageIsRed() {
        PhoneHealth.Inputs in = healthy();
        in.freeBytes = 5_000_000_000L;   // ~2%
        assertEquals(Finding.Level.RED, find(PhoneHealth.judge(in), "Storage").level);
    }

    @Test
    public void adAppsGetRemoveAndRestoreCommands() {
        PhoneHealth.Inputs in = healthy();
        in.adApps.add(new String[]{"com.miui.msa.global", "MIUI System Ads (MSA)"});
        Finding f = find(PhoneHealth.judge(in), "Ads & tracking");
        assertNotNull(f);
        assertEquals("adb shell pm uninstall --user 0 com.miui.msa.global", f.actions.get(0).target);
        assertEquals("adb shell cmd package install-existing com.miui.msa.global", f.actions.get(1).target);
        assertNull(find(PhoneHealth.judge(healthy()), "Ads & tracking"));
    }

    @Test
    public void badPatchStringIsSkipped() {
        PhoneHealth.Inputs in = healthy();
        in.securityPatch = "";
        assertNull(find(PhoneHealth.judge(in), "Updates"));
    }
}
