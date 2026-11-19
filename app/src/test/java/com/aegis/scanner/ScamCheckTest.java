package com.aegis.scanner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ScamCheckTest {

    @Test
    public void flagsKycScamAndExtractsLink() {
        ScamCheck.Result r = ScamCheck.check("Dear customer your SBI account will be blocked today. "
                + "Update KYC immediately: http://sbi-kyc-update.top/login.");
        assertTrue(r.likelyScam());
        assertEquals(1, r.links.size());
        assertEquals("http://sbi-kyc-update.top/login", r.links.get(0)); // trailing full stop stripped
    }

    @Test
    public void flagsUpiPinToReceiveMoney() {
        assertTrue(ScamCheck.check("You have received Rs 5000 cashback. Enter UPI PIN to receive money.").likelyScam());
    }

    @Test
    public void flagsHinglishElectricityThreat() {
        assertTrue(ScamCheck.check("Aapka bijli connection aaj raat 9:30 baje kat jayega. Turant call kare 9876543210").likelyScam());
    }

    @Test
    public void flagsDigitalArrestAndApk() {
        assertTrue(ScamCheck.check("This is CBI. A case is registered against you. You are under digital arrest.").likelyScam());
        assertTrue(ScamCheck.check("Install the app from this link: bit.ly/x1 rewards.apk").likelyScam());
    }

    @Test
    public void ordinaryMessageIsClean() {
        ScamCheck.Result r = ScamCheck.check("Hi, are we still meeting for lunch tomorrow at 1? Bring the photos.");
        assertEquals(0, r.score);
        assertFalse(r.likelyScam());
        assertTrue(r.links.isEmpty());
    }

    @Test
    public void ignoresEmailAddresses() {
        assertTrue(ScamCheck.check("Write to help@example.com").links.isEmpty());
    }

    @Test
    public void shizukuDurationParsing() {
        assertEquals(3_723_000L, ShizukuOps.parseDuration("1h2m3s"));
        assertEquals(2L * 86_400_000L, ShizukuOps.parseDuration("2d"));
    }
}
