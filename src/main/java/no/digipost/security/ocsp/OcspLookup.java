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
package no.digipost.security.ocsp;

import no.digipost.security.DigipostSecurityException;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;

import java.io.IOException;
import java.net.URI;

/**
 * <strong>Online Certificate Status Protocol (OCSP)</strong> is an automated certificate checking
 * network protocol. One can query an OCSP responder for the status of a certificate. The responder
 * returns whether the certificate is still trusted by the CA that issued it.
 *
 * @see <a href="http://tools.ietf.org/html/rfc6960">Internet Engineering Task Force (IETF) RFC6960</a>
 */
public final class OcspLookup {

    private static final ContentType OCSP_REQUEST_CONTENT_TYPE = ContentType.create("application/ocsp-request");

    public final URI uri;
    public final CertificateID certificateId;

    public OcspLookup(OcspLookupRequest request) {
        this(request.url, request.certificateId);
    }

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
            ClassicHttpRequest ocspRequest = ClassicRequestBuilder.post(uri)
                    .setEntity(new OCSPReqBuilder().addRequest(certificateId).build().getEncoded(), OCSP_REQUEST_CONTENT_TYPE)
                    .build();
            return client.execute(ocspRequest, res -> new OcspResult(uri, res.getCode(), EntityUtils.toByteArray(res.getEntity())));
        } catch (OCSPException | IOException e) {
            throw new DigipostSecurityException(e);
        }
    }

    @Override
    public String toString() {
        return "OCSP-lookup to responder uri " + uri;
    }


}
