package com.aegis.scanner;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class BankAppsTest {

    @Test
    public void sideloadedBankNamedAppIsFake() {
        assertNotNull(BankApps.fakeReason("SBI YONO Rewards", "com.rewards.sbi.update", false));
        assertNotNull(BankApps.fakeReason("PhonePe KYC", "com.kyc.update", false));
        assertNotNull(BankApps.fakeReason("HDFC_NetBanking", "com.hdfc.secure", false));
    }

    @Test
    public void knownFakeIdIsFakeEvenFromStore() {
        assertNotNull(BankApps.fakeReason("Rewards", "in.sbi.rewards", true));
    }

    @Test
    public void officialOrStoreAppsAreFine() {
        assertNull(BankApps.fakeReason("YONO SBI", "com.sbi.lotusintouch", false));
        assertNull(BankApps.fakeReason("SBI Card", "com.sbicard.mobile", true));
        assertNull(BankApps.fakeReason("PhonePe", "com.phonepe.app", true));
    }

    @Test
    public void ordinaryNamesDontMatch() {
        assertNull(BankApps.fakeReason("Credit Score Checker Pro", "com.example.cs", false)); // "credit" isn't "cred"
        assertNull(BankApps.fakeReason("Sbirds Game", "com.birds.game", false));
        assertNull(BankApps.fakeReason("Calculator", "com.calc", false));
    }
}
