/*
 * Copyright (C) Posten Norge AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package no.digipost.security.cert;

import no.digipost.security.DigipostSecurity;

import java.security.cert.X509Certificate;

public final class TestEnvCertificates {

    /**
     * Buypass G2 Virksomhetssertifikater for Europa (SEID v2.0) og QC eSeal (fra Q3 2021) og PSD2 QC eSeal som 'Soft Token'
     *
     * <p>CN=Buypass Class 3 Test4 CA G2 ST Business, O=Buypass AS, 2.5.4.97=#0c0f4e54524e4f2d393833313633333237, C=NO
     * <p>valid 2020-11-04 to 2040-11-04
     */
    public static X509Certificate buypassClass3TestCaG2SoftToken() {
        return BuypassClass3TestCaG2SoftToken.cert;
    }

    /**
     * Buypass G2 PSD2 QWAC
     * <p>CN=Buypass Class 3 Test4 CA G2 QC WA, O=Buypass AS, 2.5.4.97=#0c0f4e54524e4f2d393833313633333237, C=NO
     * <p>valid 2020-11-04 to 2040-11-04
     */
    public static X509Certificate buypassClass3TestCaG2Psd2QWAC() {
        return BuypassClass3TestCaG2Psd2QWAC.cert;
    }

    /**
     * Buypass G2 Virksomhetssertifikater for Europa (SEID v2.0) og QC eSeal (fra Q3 2021) og PSD2 QC eSeal som 'Soft Token'
     *
     * <p>CN=Buypass Class 3 Test4 Root CA G2 ST, O=Buypass AS, 2.5.4.97=#0c0f4e54524e4f2d393833313633333237, C=NO
     * <p>valid 2020-11-03 to 2045-11-03
     */
    public static X509Certificate buypassClass3TestRootCaG2SoftToken() {
        return BuypassClass3TestRootCaG2SoftToken.cert;
    }

    /**
     * Buypass G2 PSD2 QWAC
     *
     * <p>CN=Buypass Class 3 Test4 Root CA G2 QC, O=Buypass AS, 2.5.4.97=#0c0f4e54524e4f2d393833313633333237, C=NO
     * <p>valid 2020-11-03 to 2045-11-03
     */
    public static final X509Certificate buypassClass3TestRootCaG2Psd2QWAC() {
        return BuypassClass3TestRootCaG2Psd2QWAC.cert;
    }

    /**
     * Buypass
     *
     * <p>CN=Buypass Class 3 Test4 Root CA, O=Buypass AS-983163327, C=NO
     * <p>valid from 2010-10-06 to 2040-10-06
     */
    public static final X509Certificate buypassClass3Test4RootCa() {
        return BuypassClass3Test4RootCa.cert;
    }

    /**
     * Buypass
     *
     * <p>CN=Buypass Class 3 Test4 CA 3, O=Buypass AS-983163327, C=NO
     * <p>valid from 2012-02-16 to 2032-02-16
     */
    public static final X509Certificate buypassClass3Test4Ca3() {
        return BuypassClass3Test4Ca3.cert;
    }

    /**
     * Commfides
     *
     * <p>C=NO, O=Commfides Norge AS - 988 312 495, OU=CPN Enterprise-Norwegian SHA256 CA- TEST2, OU=Commfides Trust Environment(C) 2014 Commfides Norge AS - TEST,
     *    CN=Commfides CPN Enterprise-Norwegian SHA256 CA - TEST2
     * <p>valid from 2014-10-17 to 2022-10-03
     */
    public static final X509Certificate commfidesTestCa() {
        return CommfidesTestCa.cert;
    }

    /**
     * Commfides
     *
     * <p>C=NO, O=Commfides Norge AS - 988 312 495,OU=CPN Primary Certificate Authority TEST, OU=CPN TEST - For authorized use only,
     *    OU=Commfides Trust Environment(C) TEST 2010 Commfides Norge AS,CN=CPN Root SHA256 CA - TEST
     * <p>valid 2012-10-02 to 2022-10-03
     */
    public static final X509Certificate commfidesTestRootCa() {
        return CommfidesTestRootCa.cert;
    }



    // X509Certificate singletons

    private static final class BuypassClass3Test4Ca3 {
        static final X509Certificate cert = readCertificate("Buypass_Class_3_Test4_CA_3.cer");
    }

    private static final class BuypassClass3Test4RootCa {
        static final X509Certificate cert = readCertificate("Buypass_Class_3_Test4_Root_CA.cer");
    }

    // Buypass G2 PSD2 QWAC
    private static final class BuypassClass3TestRootCaG2Psd2QWAC {
        static final X509Certificate cert = readCertificate("BPCl3RootCaG2QC.cer");
    }

    // Buypass G2 Virksomhetssertifikater for Europa (SEID v2.0) og QC eSeal (fra Q3 2021) og PSD2 QC eSeal som 'Soft Token'
    private static final class BuypassClass3TestRootCaG2SoftToken {
        static final X509Certificate cert = readCertificate("BPCl3RootCaG2ST.cer");
    }

    // Buypass G2 PSD2 QWAC
    private static final class BuypassClass3TestCaG2Psd2QWAC {
        static final X509Certificate cert = readCertificate("BPCl3CaG2QCWA.cer");
    }

    // Buypass G2 Virksomhetssertifikater for Europa (SEID v2.0) og QC eSeal (fra Q3 2021) og PSD2 QC eSeal som 'Soft Token'
    private static final class BuypassClass3TestCaG2SoftToken {
        static final X509Certificate cert = readCertificate("BPCl3CaG2STBS.cer");
    }

    private static final class CommfidesTestRootCa {
        static final X509Certificate cert = readCertificate("commfides_test_root_ca.cer");
    }

    private static final class CommfidesTestCa {
        static final X509Certificate cert = readCertificate("commfides_test_ca.cer");
    }

    private static X509Certificate readCertificate(String resourceName) {
        return DigipostSecurity.readCertificate("certificates/test/" + resourceName);
    }

}