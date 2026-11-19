package com.aegis.scanner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;

/** Parses the real bundled databases, so a format change upstream is caught before shipping. */
public class DataParsingTest {

    private static InputStream asset(String name) throws Exception {
        return new FileInputStream("src/main/assets/" + name);
    }

    @Test
    public void mergesAllSpyAppSources() throws Exception {
        IocDb db = new IocDb();
        try (InputStream in = asset("ioc.yaml")) { db.parseYaml(in); }
        int stalkerwarePackages = db.packages.size();
        for (String f : IocDb.ANDRODR_FILES) {
            try (InputStream in = asset("androdr_" + f)) { db.parseAndroDr(in, f); }
        }
        try (InputStream in = asset(IocDb.MVT_FILE)) { db.parseMvt(in); }

        assertTrue(db.packages.size() > stalkerwarePackages);
        assertTrue("AndroDR SHA-256 certs", db.certs.keySet().stream().anyMatch(k -> k.length() == 64));
        assertTrue("APK hashes", db.hashes.size() > 1000);
        assertEquals("NoviSpy", db.packages.get("com.serv.services"));
        assertTrue("Pegasus domains", db.domains.containsValue("NSO Group Pegasus"));
        assertTrue(db.families.size() > 150);
    }

    @Test
    public void skipsDataBrokerAndMediumEntries() throws Exception {
        IocDb db = new IocDb();
        String yml = "entries:\n"
                + "- indicator: tracker.example\n  family: X\n  category: DATA_BROKER_SDK\n  severity: HIGH\n"
                + "- indicator: maybe.example\n  family: Y\n  category: MALWARE\n  severity: MEDIUM\n"
                + "- indicator: \"evil.example\"\n  family: Z\n  category: MALWARE\n  severity: CRITICAL\n";
        db.parseAndroDr(new java.io.ByteArrayInputStream(yml.getBytes("UTF-8")), "c2-domains.yml");
        assertEquals(1, db.domains.size());
        assertEquals("Z malware", db.matchDomain("cdn.evil.example"));
    }

    @Test
    public void stixConversion() throws Exception {
        String stix = "{\"objects\":[{\"type\":\"indicator\",\"pattern\":\"[domain-name:value = 'bad.example']\"},"
                + "{\"type\":\"indicator\",\"pattern\":\"[app:id = 'com.spy.app']\"},"
                + "{\"type\":\"indicator\",\"pattern\":\"[process:name = 'x']\"},{\"type\":\"malware\"}]}";
        StringBuilder out = new StringBuilder();
        IocDb.stixToTsv(stix, "Fam", out);
        assertEquals("domain\tbad.example\tFam\napp\tcom.spy.app\tFam\n", out.toString());
    }

    @Test
    public void readsExodusTrackerMirror() throws Exception {
        TrackerDb db = new TrackerDb();
        try (InputStream in = asset("trackers.yml")) { db.loadTrackersYaml(in); }
        assertTrue("signatures: " + db.size(), db.size() > 300);
    }

    @Test
    public void phishingListMatchesSubdomains() throws Exception {
        Set<String> set = new HashSet<>();
        try (InputStream in = asset("phishing_domains.txt")) { PhishDb.read(in, set); }
        assertTrue(set.size() > 1000);
        String listed = set.iterator().next();
        assertTrue(PhishDb.matches(set, "login." + listed));
        assertTrue(!PhishDb.matches(set, "example-not-listed-aegis.com"));
    }
}
