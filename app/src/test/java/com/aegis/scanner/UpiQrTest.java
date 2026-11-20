package com.aegis.scanner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class UpiQrTest {

    @Test
    public void refundQrIsAScam() {
        UpiQr.Result r = UpiQr.explain("upi://pay?pa=refund.desk@ybl&pn=Refund%20Desk&am=4999&tn=Receive%20your%20refund&cu=INR");
        assertTrue(r.upi);
        assertEquals(Finding.Level.RED, r.level);
        assertEquals("4999", r.amount);
        assertEquals("Refund Desk", r.name);
    }

    @Test
    public void bankNamedQrNeedsCare() {
        UpiQr.Result r = UpiQr.explain("upi://pay?pa=sbi.helpdesk@paytm&pn=SBI%20Customer%20Care");
        assertEquals(Finding.Level.YELLOW, r.level);
    }

    @Test
    public void shopQrIsNormal() {
        UpiQr.Result r = UpiQr.explain("upi://pay?pa=sharmagenstore@okaxis&pn=Sharma%20General%20Store&cu=INR");
        assertEquals(Finding.Level.GREEN, r.level);
        assertEquals("sharmagenstore@okaxis", r.payee);
    }

    @Test
    public void fixedAmountIsACaution() {
        assertEquals(Finding.Level.YELLOW, UpiQr.explain("upi://pay?pa=ravi@oksbi&pn=Ravi&am=250").level);
    }

    @Test
    public void websiteQrHandsBackTheLink() {
        UpiQr.Result r = UpiQr.explain("https://sbi-kyc-update.top/login");
        assertFalse(r.upi);
        assertEquals("https://sbi-kyc-update.top/login", r.link);
    }
}
