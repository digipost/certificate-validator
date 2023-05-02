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
package no.digipost.security.cert.internal;


import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;

import static java.util.stream.Collectors.joining;
import static javax.security.auth.x500.X500Principal.RFC1779;

public final class JavaSecurityUtils {

    /**
     * String denoting the certificate type {@value #X509}.
     */
    public static final String X509 = "X.509";


    public static CertificateFactory getX509CertificateFactory() {
         try {
            return CertificateFactory.getInstance(X509);
        } catch (CertificateException e) {
            throw new RuntimeException(
                    "Could not create " + X509 + " certificate factory: '" + e.getMessage() + "'. " +
                    "Available providers: " + Stream.of(Security.getProviders()).map(Provider::getName).collect(joining(", ")), e);
        }
    }


    public static String describe(CertPath certPath) {
        if (certPath == null) {
            return "(null)";
        }
        List<? extends Certificate> certificates = certPath.getCertificates();
        if (!certificates.isEmpty()) {
            return certificates.stream().map(JavaSecurityUtils::describe).collect(joining("\n ^-- Issued by: ", "CertPath with the following certificates:\nCertificate: ", ""));
        } else {
            return "CertPath with no certificates";
        }
    }


    public static String describe(Certificate certificate) {
        if (certificate == null) {
            return "(null)";
        }
        if (certificate instanceof X509Certificate) {
            X509Certificate x509 = (X509Certificate) certificate;
            String subjectDescription = x509.getSubjectX500Principal().getName(RFC1779);
            String validityDescription = "valid from " + x509.getNotBefore().toInstant() + " to " + x509.getNotAfter().toInstant();
            String serialNumberDescription = "serial-number: " + x509.getSerialNumber().toString(16);
            String issuerDescription = x509.getSubjectX500Principal().equals(x509.getIssuerX500Principal()) ? "self-issued" : "issuer: " + x509.getIssuerX500Principal().getName(RFC1779);
            return String.join(", ", subjectDescription, validityDescription, serialNumberDescription, issuerDescription);
        } else {
            return certificate.getType() + "-certificate";
        }
    }


    private JavaSecurityUtils() {
    }
}
