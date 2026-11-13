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

import no.digipost.security.crl.CrlLookup;
import no.digipost.security.crl.CrlProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static no.digipost.security.DigipostSecurity.describe;
import static no.digipost.security.cert.CertStatus.OK;
import static no.digipost.security.cert.CertStatus.REVOKED;
import static no.digipost.security.crl.CrlUtils.findCrlDistributionPoints;
import static no.digipost.security.crl.CrlUtils.isUsableCrlFor;

/**
 * Determines revocation status of a certificate using CRLs, either provided by a {@link CrlProvider},
 * or downloaded from the CRL distribution points of the certificate. Downloaded CRLs are cached
 * until their {@code nextUpdate}.
 */
final class CrlChecker {

    private static final Logger LOG = LoggerFactory.getLogger(CrlChecker.class);

    private final CloseableHttpClient client;
    private final Clock clock;
    private final Map<URI, X509CRL> downloadedCrls = new ConcurrentHashMap<>();

    CrlChecker(CloseableHttpClient client, Clock clock) {
        this.client = client;
        this.clock = clock;
    }


    /**
     * @return {@link CertStatus#OK} or {@link CertStatus#REVOKED} if a usable CRL was found, or
     *         {@link Optional#empty()} if revocation status could not be determined using CRL.
     */
    Optional<CertStatus> check(X509Certificate certificate, X509Certificate issuer, CrlProvider crlProvider) {
        Instant now = clock.instant();
        Optional<X509CRL> crl = crlProvider.crlIssuedBy(issuer).filter(provided -> isUsableCrlFor(provided, issuer, now));
        if (!crl.isPresent()) {
            crl = findCrlDistributionPoints(certificate).stream()
                    .map(uri -> getDownloadedCrl(uri, issuer, now))
                    .filter(Optional::isPresent).map(Optional::get)
                    .findFirst();
        }
        return crl.map(c -> {
            if (c.isRevoked(certificate)) {
                LOG.info("{} is revoked according to CRL from {}", describe(certificate), describe(issuer));
                return REVOKED;
            }
            return OK;
        });
    }


    private Optional<X509CRL> getDownloadedCrl(URI uri, X509Certificate issuer, Instant now) {
        X509CRL cached = downloadedCrls.get(uri);
        if (cached != null && isUsableCrlFor(cached, issuer, now)) {
            return Optional.of(cached);
        }
        CrlLookup lookup = new CrlLookup(uri);
        try {
            X509CRL downloaded = lookup.executeUsing(client);
            if (isUsableCrlFor(downloaded, issuer, now)) {
                downloadedCrls.put(uri, downloaded);
                return Optional.of(downloaded);
            }
        } catch (RuntimeException e) {
            LOG.warn("Failed {} for issuer {}: {} '{}'", lookup, describe(issuer), e.getClass().getSimpleName(), e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getClass().getSimpleName() + ": '" + e.getMessage() + "'", e);
            }
        }
        return Optional.empty();
    }
}
