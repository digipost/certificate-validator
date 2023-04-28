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

import no.digipost.security.cert.internal.JavaSecurityUtils;
import org.apache.http.ssl.TrustStrategy;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


/**
 * Used for configuring a HTTP Client to check if the server's certificate is revoked.
 * The check is performed against a static Certificate Revocation List (CRL) file.
 *
 * When configuring the {@link javax.net.ssl.SSLContext} for a {@link org.apache.http.client.HttpClient},
 * the RevocationChecker is set up as follows:
 *
 * <pre>{@code
 *  HttpClientBuilder.create()
 *      .setSSLContext(SSLContexts.custom()
 *          .loadTrustMaterial(trustStore, new RevocationChecker(crlPath))
 *      ).build();
 * }</pre>
 *
 */

public class RevocationChecker implements TrustStrategy {

    private final CRL crl;

    public RevocationChecker(Path crlPath) {
        CertificateFactory cf = JavaSecurityUtils.getX509CertificateFactory();
        try (InputStream inputStream = Files.newInputStream(crlPath)) {
            this.crl = cf.generateCRL(inputStream);
        } catch (CRLException | IOException e) {
            throw new RuntimeException("Could not load CRL from path '" + crlPath + "'.", e);
        }
    }

    @Override
    public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        for(X509Certificate certificate : chain) {
            if (crl.isRevoked(certificate)) {
                throw new CertificateException(
                        "Certificate with serial number " + certificate.getSerialNumber().toString(16) +
                        " is revoked: " + JavaSecurityUtils.describe(certificate));
            }
        }
        return false;
    }
}
