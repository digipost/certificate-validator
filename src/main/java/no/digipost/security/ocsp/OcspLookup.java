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

import no.digipost.security.DigipostSecurityException;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.apache.http.client.methods.RequestBuilder.post;

/**
 * <strong>Online Certificate Status Protocol (OCSP)</strong> is an automated certificate checking
 * network protocol. One can query an OCSP responder for the status of a certificate. The responder
 * returns whether the certificate is still trusted by the CA that issued it.
 *
 * @see <a href="http://tools.ietf.org/html/rfc6960">Internet Engineering Task Force (IETF) RFC6960</a>
 */
public final class OcspLookup {

    /**
     * Prepare a new OCSP lookup request for the given certificate.
     *
     * @param certificate the certificate to lookup. It must contain an OCSP responder URI.
     * @param issuer the issuer of the certificate.
     * @return an OCSP request, ready to be {@link OcspLookup#executeUsing(CloseableHttpClient) executed},
     *         or {@link Optional#empty()} if no OCSP responder URI was found, or any other error occuring.
     */
    public static Optional<OcspLookup> newLookup(X509Certificate certificate, X509Certificate issuer) {
        return OcspUtils.findOcspResponderUrl(certificate)
                .flatMap(ocspResponderUri ->
                    OcspUtils.certificateIdForOcsp(certificate, issuer).map(certId -> new OcspLookup(ocspResponderUri, certId)));
    }


    public final URI uri;
    public final CertificateID certificateId;

    private OcspLookup(URI responderUri, CertificateID certificateId) {
        this.certificateId = certificateId;
        this.uri = responderUri;
    }

    /**
     * Execute the OCSP lookup request.
     *
     * @param client the http client to use for executing the lookup request.
     * @return the {@link OcspResult result} of the OCSP lookup.
     */
    public OcspResult executeUsing(CloseableHttpClient client) {
        try {
            HttpEntity ocspRequestEntity = new ByteArrayEntity(new OCSPReqBuilder().addRequest(certificateId).build().getEncoded());
            HttpUriRequest ocspRequest = post(uri)
                    .addHeader("Content-Type", "application/ocsp-request")
                    .setEntity(ocspRequestEntity).build();
            return new OcspResult(uri, client.execute(ocspRequest));
        } catch (OCSPException | IOException e) {
            throw new DigipostSecurityException(e);
        }
    }

    @Override
    public String toString() {
        return "OCSP-lookup to responder uri " + uri;
    }


}
