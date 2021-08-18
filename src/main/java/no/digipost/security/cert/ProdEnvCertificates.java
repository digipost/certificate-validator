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

public final class ProdEnvCertificates {

    /**
     * Buypass G2 Virksomhetssertifikater for Europa (SEID v2.0) og QC eSeal (fra Q3 2021) og PSD2 QC eSeal som 'Soft Token'
     *
     * <p>CN=Buypass Class 3 CA G2 ST Business, O=Buypass AS, 2.5.4.97=#0c0f4e54524e4f2d393833313633333237, C=NO
     * <p>valid 2020-11-04 to 2040-11-04
     */
    public static X509Certificate buypassClass3CaG2SoftToken() {
        return BuypassClass3CaG2SoftToken.cert;
    }

    /**
     * Buypass G2 PSD2 QWAC
     * <p>CN=Buypass Class 3 CA G2 QC WA, O=Buypass AS, 2.5.4.97=#0c0f4e54524e4f2d393833313633333237, C=NO
     * <p>valid 2020-11-04 to 2040-11-04
     */
    public static X509Certificate buypassClass3CaG2Psd2QWAC() {
        return BuypassClass3CaG2Psd2QWAC.cert;
    }

    /**
     * Buypass G2 Virksomhetssertifikater for Europa (SEID v2.0) og QC eSeal (fra Q3 2021) og PSD2 QC eSeal som 'Soft Token'
     *
     * <p>CN=Buypass Class 3 Root CA G2 ST, O=Buypass AS, 2.5.4.97=#0c0f4e54524e4f2d393833313633333237, C=NO
     * <p>valid 2020-11-03 to 2045-11-03
     */
    public static X509Certificate buypassClass3RootCaG2SoftToken() {
        return BuypassClass3RootCaG2SoftToken.cert;
    }

    /**
     * Buypass G2 PSD2 QWAC
     *
     * <p>CN=Buypass Class 3 Root CA G2 QC, O=Buypass AS, 2.5.4.97=#0c0f4e54524e4f2d393833313633333237, C=NO
     * <p>valid 2020-11-03 to 2045-11-03
     */
    public static final X509Certificate buypassClass3RootCaG2Psd2QWAC() {
        return BuypassClass3RootCaG2Psd2QWAC.cert;
    }

    /**
     * Buypass
     *
     * <p>C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Root CA
     * <p>valid 2010-10-26 to 2040-10-26
     */
    public static final X509Certificate buypassClass3RootCa() {
        return BuypassClass3RootCa.cert;
    }

    /**
     * Buypass
     *
     * <p>CN=Buypass Class 3 CA 3, O=Buypass AS-983163327, C=NO
     * <p>valid 2012-09-25 to 2032-09-25
     */
    public static final X509Certificate buypassClass3Ca3() {
        return BuypassClass3Ca3.cert;
    }

    /**
     * Commfides
     *
     * <p>CN=CPN RootCA SHA256 Class 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO
     * <p>valid 2011-02-28 to 2025-01-01
     */
    public static final X509Certificate commfidesRootCa() {
        return CommfidesRootCa.cert;
    }

    /**
     * Commfides
     *
     * <p>C=NO, O=Commfides Norge AS - 988 312 495, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, CN=CPN Enterprise SHA256 CLASS 3
     * <p>valid 2011-02-28 to 2024-12-31
     */
    public static final X509Certificate commfidesCa() {
        return CommfidesCa.cert;
    }



    // X509Certificate singletons

    private static final class BuypassClass3RootCa {
        static final X509Certificate cert = readCertificate("BPClass3RootCA.cer");
    }

    private static final class BuypassClass3Ca3 {
        static final X509Certificate cert = readCertificate("BPClass3CA3.cer");
    }

    // Buypass G2 PSD2 QWAC
    private static final class BuypassClass3RootCaG2Psd2QWAC {
        static final X509Certificate cert = readCertificate("BPCl3RootCaG2QC.cer");
    }

    // Buypass G2 Virksomhetssertifikater for Europa (SEID v2.0) og QC eSeal (fra Q3 2021) og PSD2 QC eSeal som 'Soft Token'
    private static final class BuypassClass3RootCaG2SoftToken {
        static final X509Certificate cert = readCertificate("BPCl3RootCaG2ST.cer");
    }

    // Buypass G2 PSD2 QWAC
    private static final class BuypassClass3CaG2Psd2QWAC {
        static final X509Certificate cert = readCertificate("BPCl3CaG2QCWA.cer");
    }

    // Buypass G2 Virksomhetssertifikater for Europa (SEID v2.0) og QC eSeal (fra Q3 2021) og PSD2 QC eSeal som 'Soft Token'
    private static final class BuypassClass3CaG2SoftToken {
        static final X509Certificate cert = readCertificate("BPCl3CaG2STBS.cer");
    }

    private static final class CommfidesRootCa {
        static final X509Certificate cert = readCertificate("commfides_root_ca.cer");
    }

    private static final class CommfidesCa {
        static final X509Certificate cert = readCertificate("commfides_ca.cer");
    }

    private static X509Certificate readCertificate(String resourceName) {
        return DigipostSecurity.readCertificate("certificates/prod/" + resourceName);
    }

    private ProdEnvCertificates() {
    }

}
