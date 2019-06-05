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
package no.digipost.security.ocsp;

import org.bouncycastle.cert.ocsp.CertificateID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static no.digipost.security.DigipostSecurity.describe;
import static no.digipost.security.ocsp.OcspUtils.findOcspResponderUrl;
import static no.digipost.security.ocsp.OcspUtils.tryCreateCertificateId;

public final class OcspLookupRequest {

    /**
     * Create a new OCSP lookup request, if possible to resolve OCSP responder URL.
     *
     * @param certificate the certificate to lookup OCSP status for
     * @param issuer the issuer of the certificate
     *
     * @return a new OCSP lookup request, or {@link Optional#empty()} if no OCSP responder URL could be resolved
     */
    public static Optional<OcspLookupRequest> tryCreate(X509Certificate certificate, X509Certificate issuer) {
        return findOcspResponderUrl(certificate)
                .flatMap(url -> tryCreateCertificateId(certificate, issuer)
                        .map(id -> new OcspLookupRequest(url, id, describe(certificate))));
    }

    static final Logger LOG = LoggerFactory.getLogger(OcspLookupRequest.class);

    public final URI url;
    public final BigInteger certificateSerialNumber;

    final CertificateID certificateId;

    private final String certificateDescription;

    private OcspLookupRequest(URI ocspResponderUrl, CertificateID certificateId, String certificateDescription) {
        this.url = ocspResponderUrl;
        this.certificateSerialNumber = certificateId.getSerialNumber();
        this.certificateId = certificateId;
        this.certificateDescription = certificateDescription +
                (certificateDescription.contains(String.valueOf(certificateSerialNumber)) ? "" : " (serial number " + certificateSerialNumber + ")");
    }


    @Override
    public String toString() {
        return "OCSP-lookup request to " + url + " for " + certificateDescription;
    }

}
