/**
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

import no.digipost.security.ocsp.OcspLookupRequest;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static no.digipost.security.DigipostSecurity.describe;
import static no.digipost.security.cert.CertHelper.getOrganizationUnits;


/**
 * A certificate and its issuer, already determined to be trusted.
 * This class is never instantiated unless the certificate and issuer
 * has been validated as trusted.
 */
public final class TrustedCertificateAndIssuer {

    /**
     * The trusted certificate.
     */
    public final X509Certificate certificate;

    /**
     * The trusted issuer of {@link #certificate}.
     */
    public final X509Certificate issuer;

    /**
     * The OCSP lookup request for the certificate, if possible to resolve, which
     * may be used to perform an OCSP-lookup for this certificate.
     */
    public final Optional<OcspLookupRequest> ocspLookupRequest;


    TrustedCertificateAndIssuer(X509Certificate trustedCertificate, X509Certificate trustedIssuer) {
        this.certificate = trustedCertificate;
        this.issuer = trustedIssuer;
        this.ocspLookupRequest = OcspLookupRequest.tryCreate(trustedCertificate, trustedIssuer);
    }

    boolean isIssuedByDigipostCA() {
        return getOrganizationUnits(issuer).anyMatch("Digipost"::equals);
    }

    @Override
    public String toString() {
        return "Trusted certificate: " + describe(certificate) + ", issued by " + describe(issuer) + ", " +
                ocspLookupRequest.map(request -> "OCSP-lookup may be done at " + request.url).orElse("OCSP-lookup is not possible");
    }
}
