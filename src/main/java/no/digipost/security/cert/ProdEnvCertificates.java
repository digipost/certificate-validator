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


/**
 * Certificates applicable for use in production environment.
 * <p>
 * Sources:
 * <ul>
 *   <li><a href="https://www.buypass.no/sikkerhet/buypass-rotsertifikater">Buypass</a></li>
 * </ul>
 *
 * @see TestEnvCertificates
 */
public final class ProdEnvCertificates {

    /**
     * Buypass Class 3 Root CA G2 'Soft Token'
     *
     * <p>CN=Buypass Class 3 Root CA G2 ST, O=Buypass AS, OID.2.5.4.97=NTRNO-983163327, C=NO
     * <p>valid 2020-11-10 to 2045-11-1
     */
    public static X509Certificate buypassClass3RootCaG2SoftToken() {
        return BuypassClass3RootCaG2ST.cert;
    }

    /**
     * Buypass SEID v2.0 Enterprise certificate issuer CA G2 'Soft Token' Business
     *
     * <p>CN=Buypass Class 3 CA G2 ST Business, O=Buypass AS, OID.2.5.4.97=NTRNO-983163327, C=NO
     * <p>valid 2020-11-10 to 2040-11-10
     */
    public static X509Certificate buypassClass3CaG2SoftToken() {
        return BuypassClass3CaG2ST.cert;
    }

    /**
     * Buypass Class 3 Root CA G2 'Hard Token'
     *
     * <p>CN=Buypass Class 3 Root CA G2 HT, O=Buypass AS, OID.2.5.4.97=NTRNO-983163327, C=NO
     * <p>valid 2020-11-10 to 2045-11-10
     */
    public static X509Certificate buypassClass3RootCaG2HardToken() {
        return BuypassClass3RootCaG2HT.cert;
    }

    /**
     * Buypass SEID v2.0 Enterprise certificate issuer CA G2 'Hard Token'
     *
     * <p>CN=Buypass Class 3 CA G2 HT Business, O=Buypass AS, OID.2.5.4.97=NTRNO-983163327, C=NO
     * <p>valid 2020-11-10 to 2040-11-10
     */
    public static X509Certificate buypassClass3CaG2HardToken() {
        return BuypassClass3CaG2HT.cert;
    }


    /**
     * Buypass Root CA (SEID generation 1)
     *
     * <p>CN=Buypass Class 3 Root CA, O=Buypass AS-983163327, C=NO
     * <p>valid 2010-10-26 to 2040-10-26
     */
    public static X509Certificate buypassClass3RootCa() {
        return BuypassClass3RootCa.cert;
    }

    /**
     * Buypass certificate issuer CA (SEID generation 1)
     *
     * <p>CN=Buypass Class 3 CA 3, O=Buypass AS-983163327, C=NO
     * <p>valid 2012-09-25 to 2032-09-25
     */
    public static X509Certificate buypassClass3Ca3() {
        return BuypassClass3Ca3.cert;
    }

    /**
     * Commfides Root CA (SEID generaation 1)
     *
     * <p>C=NO, O=Commfides Norge AS - 988 312 495, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, CN=CPN RootCA SHA256 Class 3
     * <p>valid 2011-02-28 to 2025-01-01
     */
    public static X509Certificate commfidesRootCa() {
        return CommfidesRootCa.cert;
    }

    /**
     * Commfides certificate issuer CA (SEID generation 1)
     *
     * <p>C=NO, O=Commfides Norge AS - 988 312 495, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, CN=CPN Enterprise SHA256 CLASS 3
     * <p>valid 2011-02-28 to 2024-12-31
     */
    public static X509Certificate commfidesCa() {
        return CommfidesCa.cert;
    }



    // X509Certificate singletons

    private static final class BuypassClass3RootCa {
        static final X509Certificate cert = readCertificate("BPClass3RootCA.cer");
    }

    private static final class BuypassClass3Ca3 {
        static final X509Certificate cert = readCertificate("BPClass3CA3.cer");
    }

    private static final class BuypassClass3RootCaG2ST {
        static final X509Certificate cert = readCertificate("BPCl3RootCaG2ST.cer");
    }

    private static final class BuypassClass3CaG2ST {
        static final X509Certificate cert = readCertificate("BPCl3CaG2STBS.cer");
    }

    private static final class BuypassClass3RootCaG2HT {
        static final X509Certificate cert = readCertificate("BPCl3RootCaG2HT.cer");
    }

    private static final class BuypassClass3CaG2HT {
        static final X509Certificate cert = readCertificate("BPCl3CaG2HTBS.cer");
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
