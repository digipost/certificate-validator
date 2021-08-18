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
