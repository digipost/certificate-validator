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

import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import static java.util.stream.Stream.concat;
import static no.digipost.security.DigipostSecurity.readCertificate;

public class BuypassCommfidesCertificates {

    public static Trust createProdTrust() {
        return new Trust(initTrustedCerts(false), initIntermediateTrust(false));
    }

    public static Trust createTestTrust() {
        return new Trust(initTrustedCerts(true), initIntermediateTrust(true));
    }

    public static Trust createTestTrustIncluding(X509Certificate ... additionalTrustedCerts) {
        return new Trust(concat(initTrustedCerts(true), Stream.of(additionalTrustedCerts)), initIntermediateTrust(true));
    }

    private static Stream<X509Certificate> initTrustedCerts(boolean includeTestCerts) {
        Stream.Builder<X509Certificate> trustedCerts = Stream.builder();

        // Buypass gyldig 2010 - 2040 - C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Root CA
        trustedCerts.add(readCertificate("sertifikater/prod/BPClass3RootCA.cer"));
        // commfides gyldig 2011 - 2024 - CN=CPN RootCA SHA256 Class 3, OU=Commfides Trust Environment (c) 2011 Commfides Norge AS, O=Commfides Norge AS - 988 312 495, C=NO
        trustedCerts.add(readCertificate("sertifikater/prod/commfides_root_ca.cer"));

        if (includeTestCerts) {
            // Buypass gyldig 2010 - 2040 - C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Test4 Root CA
            trustedCerts.add(readCertificate("sertifikater/test/Buypass_Class_3_Test4_Root_CA.cer"));
            // Buypass gyldig 2012 - 2022 - CN=CPN Root SHA256 CA - TEST, OU=Commfides Trust Environment(C) TEST 2010 Commfides Norge AS, OU=CPN TEST - For authorized use only, OU=CPN Primary Certificate Authority TEST, O=Commfides Norge AS - 988 312 495, C=NO
            trustedCerts.add(readCertificate("sertifikater/test/commfides_test_root_ca.cer"));
        }
        return trustedCerts.build();
    }


    private static Stream<X509Certificate> initIntermediateTrust(boolean includeTestCerts) {
        Stream.Builder<X509Certificate> intermediateTrust = Stream.builder();

        //2012-2032
        intermediateTrust.add(readCertificate("sertifikater/prod/BPClass3CA3.cer"));
        //2011-2025
        intermediateTrust.add(readCertificate("sertifikater/prod/commfides_ca.cer"));

        if (includeTestCerts) {
            //2012-2032
            intermediateTrust.add(readCertificate("sertifikater/test/Buypass_Class_3_Test4_CA_3.cer"));
            //2012-2022
            intermediateTrust.add(readCertificate("sertifikater/test/commfides_test_ca.cer"));
        }

        return intermediateTrust.build();
    }

}
