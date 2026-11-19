package com.aegis.scanner;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Asks the phone's security chip (TEE / StrongBox) whether the bootloader is locked and the
 * system passed Verified Boot, using Android key attestation. Unlike file checks for "su",
 * this can't be faked by a modified Android unless the chip itself is broken.
 *
 * shortcut: doesn't check Google's attestation revocation list (needs internet); add a fetch of
 * https://android.googleapis.com/attestation/status if leaked keys become a real problem.
 */
public final class Attestation {

    public static final int VERIFIED = 0, SELF_SIGNED = 1, UNVERIFIED = 2, FAILED = 3;

    public static final class Result {
        public boolean trustedRoot, deviceLocked;
        public int verifiedBootState = -1;
    }

    /** SHA-256 of the SubjectPublicKeyInfo of Google's hardware attestation roots (android.googleapis.com/attestation/root). */
    private static final Set<String> GOOGLE_ROOTS = new HashSet<>(Arrays.asList(
            "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae", // RSA root (2016, re-issued 2022)
            "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec"  // EC "Key Attestation CA1"
    ));

    private static final String OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final int TAG_ROOT_OF_TRUST = 704;
    private static final String ALIAS = "aegis_attestation_probe";

    /** Returns null when the phone has no hardware attestation (or it failed). */
    public static Result check() {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            byte[] challenge = new byte[16];
            new SecureRandom().nextBytes(challenge);
            KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            g.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build());
            g.generateKeyPair();
            Certificate[] chain = ks.getCertificateChain(ALIAS);
            if (chain == null || chain.length < 2) return null;

            Result r = new Result();
            r.trustedRoot = chainIsValid(chain);
            X509Certificate leaf = (X509Certificate) chain[0];
            byte[] ext = leaf.getExtensionValue(OID);
            if (ext == null) return null;
            Der octet = Der.read(ext, 0);                       // extension value is wrapped in an OCTET STRING
            Der[] desc = Der.read(ext, octet.valueStart).children(ext);
            if (desc.length < 8) return null;
            if (Der.intValue(ext, desc[1]) == 0) return null;   // attestationSecurityLevel = Software: proves nothing
            if (!Arrays.equals(Der.bytes(ext, desc[4]), challenge)) r.trustedRoot = false; // replayed answer
            for (Der e : desc[7].children(ext)) {               // hardwareEnforced AuthorizationList
                if (e.tagNumber != TAG_ROOT_OF_TRUST) continue;
                Der[] rot = Der.read(ext, e.valueStart).children(ext);
                r.deviceLocked = ext[rot[1].valueStart] != 0;
                r.verifiedBootState = Der.intValue(ext, rot[2]);
                return r;
            }
            return null;
        } catch (Throwable t) {
            return null;
        } finally {
            try { if (ks != null) ks.deleteEntry(ALIAS); } catch (Exception ignored) { }
        }
    }

    private static boolean chainIsValid(Certificate[] chain) {
        try {
            for (int i = 0; i < chain.length - 1; i++) chain[i].verify(chain[i + 1].getPublicKey());
            Certificate root = chain[chain.length - 1];
            root.verify(root.getPublicKey());
            String h = Net.hex(MessageDigest.getInstance("SHA-256").digest(root.getPublicKey().getEncoded()));
            return GOOGLE_ROOTS.contains(h);
        } catch (Exception e) {
            return false;
        }
    }

    /** Minimal DER reader: just enough for the attestation extension. */
    static final class Der {
        int tagNumber, valueStart, valueLen, end;

        static Der read(byte[] b, int pos) {
            Der d = new Der();
            int first = b[pos++] & 0xFF;
            int tag = first & 0x1F;
            if (tag == 0x1F) {                                   // high tag number (e.g. [704])
                tag = 0;
                int x;
                do { x = b[pos++] & 0xFF; tag = (tag << 7) | (x & 0x7F); } while ((x & 0x80) != 0);
            }
            int len = b[pos++] & 0xFF;
            if (len > 0x80) {
                int n = len & 0x7F;
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | (b[pos++] & 0xFF);
            }
            d.tagNumber = tag;
            d.valueStart = pos;
            d.valueLen = len;
            d.end = pos + len;
            if (d.end > b.length) throw new IllegalArgumentException("bad DER");
            return d;
        }

        Der[] children(byte[] b) {
            java.util.List<Der> out = new java.util.ArrayList<>();
            for (int p = valueStart; p < end; ) {
                Der c = read(b, p);
                out.add(c);
                p = c.end;
            }
            return out.toArray(new Der[0]);
        }

        static int intValue(byte[] b, Der d) {
            int v = 0;
            for (int i = d.valueStart; i < d.end; i++) v = (v << 8) | (b[i] & 0xFF);
            return v;
        }

        static byte[] bytes(byte[] b, Der d) {
            return Arrays.copyOfRange(b, d.valueStart, d.end);
        }
    }
}
