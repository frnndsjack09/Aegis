package com.aegis.scanner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class CallGuardTest {

    @Test
    public void warnsOncePerAppPerCall() {
        CallGuard g = CallGuard.newCall();
        assertTrue(g.shouldWarn("com.phonepe.app"));
        assertFalse(g.shouldWarn("com.phonepe.app"));        // same call, same app: once
        assertTrue(g.shouldWarn("com.anydesk.anydeskandroid"));
        assertTrue(CallGuard.newCall().shouldWarn("com.phonepe.app")); // next call warns again
    }

    @Test
    public void ignoresOrdinaryApps() {
        CallGuard g = CallGuard.newCall();
        assertFalse(g.shouldWarn("com.google.android.youtube"));
        assertNull(CallGuard.kind("com.android.chrome"));
    }

    @Test
    public void screenSharingGetsTheStrongerWarning() {
        assertEquals("screen-sharing", CallGuard.kind("com.teamviewer.quicksupport.market"));
        assertEquals("money", CallGuard.kind("com.sbi.lotusintouch"));
        assertTrue(CallGuard.title("AnyDesk", "screen-sharing").startsWith("⚠"));
    }
}
