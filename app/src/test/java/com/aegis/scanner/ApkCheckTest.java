package com.aegis.scanner;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ApkCheckTest {

    private static ApkCheck.Facts app(String file, String label, String... perms) {
        ApkCheck.Facts f = new ApkCheck.Facts();
        f.parsed = true;
        f.fileName = file;
        f.label = label;
        f.pkg = "com.example.app";
        for (String p : perms) f.perms.add("android.permission." + p);
        return f;
    }

    @Test
    public void weddingInviteThatReadsSmsIsRed() {
        ApkCheck.Verdict v = ApkCheck.judge(app("Wedding_Invite.apk", "Invitation", "READ_SMS", "RECEIVE_SMS"));
        assertEquals(Finding.Level.RED, v.level);
    }

    @Test
    public void fakeBankAppWithAccessibilityIsRed() {
        ApkCheck.Facts f = app("SBI_YONO_Rewards.apk", "SBI Rewards");
        f.accessibilityService = true;
        assertEquals(Finding.Level.RED, ApkCheck.judge(f).level);
    }

    @Test
    public void ordinaryGameIsGreen() {
        assertEquals(Finding.Level.GREEN, ApkCheck.judge(app("puzzle-2048.apk", "2048", "INTERNET", "VIBRATE")).level);
    }

    @Test
    public void lureNameAloneIsOnlyACaution() {
        assertEquals(Finding.Level.YELLOW, ApkCheck.judge(app("RTO_Challan.apk", "Challan", "INTERNET")).level);
    }

    @Test
    public void knownMalwareAndFakeUpdateWinOverEverything() {
        ApkCheck.Facts f = app("game.apk", "Game");
        f.iocFamily = "SpyNote";
        f.iocHow = "signing certificate";
        assertEquals(Finding.Level.RED, ApkCheck.judge(f).level);

        ApkCheck.Facts g = app("WhatsApp.apk", "WhatsApp");
        g.installedLabel = "WhatsApp";
        g.signerDiffers = true;
        ApkCheck.Verdict v = ApkCheck.judge(g);
        assertEquals(Finding.Level.RED, v.level);
        assertEquals("Fake copy of WhatsApp", v.headline);
    }

    @Test
    public void sameDeveloperAsInstalledAppIsGenuineWhateverTheName() {
        ApkCheck.Facts f = app("Wedding_Invite.apk", "Messages", "READ_SMS");
        f.installedLabel = "Messages";
        f.sameSigner = true;
        assertEquals(Finding.Level.GREEN, ApkCheck.judge(f).level);
    }

    @Test
    public void unreadableFileIsYellow() {
        assertEquals(Finding.Level.YELLOW, ApkCheck.judge(new ApkCheck.Facts()).level);
    }
}
