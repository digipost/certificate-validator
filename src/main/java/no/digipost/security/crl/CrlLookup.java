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
package no.digipost.security.crl;

import no.digipost.security.DigipostSecurityException;
import no.digipost.security.cert.internal.JavaSecurityUtils;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;

/**
 * Download of a CRL from a CRL distribution point.
 */
public final class CrlLookup {

    static final int MAX_CRL_SIZE_BYTES = 10 * 1024 * 1024;

    public final URI uri;

    public CrlLookup(URI uri) {
        this.uri = uri;
    }

    /**
     * Download and parse the CRL. The CRL is <em>not</em> verified, see
     * {@link CrlUtils#isUsableCrlFor(X509CRL, java.security.cert.X509Certificate, java.time.Instant)}.
     *
     * @param client the http client to use for downloading the CRL.
     * @return the downloaded CRL
     * @throws DigipostSecurityException if the CRL could not be downloaded or parsed
     */
    public X509CRL executeUsing(CloseableHttpClient client) {
        ClassicHttpRequest request = ClassicRequestBuilder.get(uri).build();
        try {
            byte[] crlBytes = client.execute(request, response -> {
                if (response.getCode() != 200) {
                    throw new IOException("Unexpected HTTP status " + response.getCode() + " from " + uri);
                }
                return EntityUtils.toByteArray(response.getEntity(), MAX_CRL_SIZE_BYTES);
            });
            if (crlBytes == null) {
                throw new IOException("Empty response from " + uri);
            }
            return (X509CRL) JavaSecurityUtils.getX509CertificateFactory().generateCRL(new ByteArrayInputStream(crlBytes));
        } catch (IOException | CRLException e) {
            throw new DigipostSecurityException(e);
        }
    }

    @Override
    public String toString() {
        return "CRL-lookup to " + uri;
    }
}
