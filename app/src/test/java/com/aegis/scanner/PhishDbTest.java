package com.aegis.scanner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Set;

public class PhishDbTest {

    @Test
    public void hashedSetMatchesListedDomainsAndParents() {
        String[] lines = {"# comment", "", "Evil-Bank.xyz", "www.phish.example.com", "evil-bank.xyz"};
        long[] raw = new long[lines.length];
        int n = 0;
        for (String l : lines) {
            String d = PhishDb.clean(l);
            if (d != null) raw[n++] = PhishDb.hash(d);
        }
        Set<String> set = new PhishDb.HashedSet(raw, n);
        assertEquals(2, set.size()); // duplicates collapse
        assertTrue(PhishDb.matches(set, "login.evil-bank.xyz"));
        assertTrue(PhishDb.matches(set, "phish.example.com"));
        assertFalse(PhishDb.matches(set, "example.com"));
        assertFalse(PhishDb.matches(set, "good-bank.xyz"));
    }
}
