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
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.time.temporal.ChronoUnit.HOURS;
import static no.digipost.security.DigipostSecurity.describe;
import static no.digipost.security.cert.CertStatus.OK;
import static no.digipost.security.cert.CertStatus.REVOKED;
import static no.digipost.security.crl.CrlUtils.findCrlDistributionPoints;
import static no.digipost.security.crl.CrlUtils.isUsableCrlFor;

/**
 * Checks revocation with CRLs from a {@link CrlProvider} or the certificate's CRL distribution points.
 * Downloaded CRLs are downloaded again when they are older than {@link #MAX_AGE_OF_DOWNLOADED_CRL},
 * but are still used until their {@code nextUpdate} if a new CRL can not be downloaded.
 */
final class CrlChecker {

    private static final Logger LOG = LoggerFactory.getLogger(CrlChecker.class);

    static final Duration MAX_AGE_OF_DOWNLOADED_CRL = Duration.of(1, HOURS);

    private final CloseableHttpClient client;
    private final Clock clock;
    private final Map<URI, DownloadedCrl> downloadedCrls = new ConcurrentHashMap<>();

    CrlChecker(CloseableHttpClient client, Clock clock) {
        this.client = client;
        this.clock = clock;
    }


    /**
     * @return {@link CertStatus#OK} or {@link CertStatus#REVOKED}, or empty if no usable CRL was found
     */
    Optional<CertStatus> check(X509Certificate certificate, X509Certificate issuer, CrlProvider crlProvider) {
        Instant now = clock.instant();
        Optional<X509CRL> crl = crlProvider.crlsIssuedBy(issuer).stream()
                .filter(provided -> isUsableCrlFor(provided, certificate, issuer, now))
                .max(Comparator.comparing(X509CRL::getThisUpdate));
        if (!crl.isPresent()) {
            crl = findCrlDistributionPoints(certificate).stream()
                    .map(uri -> getDownloadedCrl(uri, certificate, issuer, now))
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


    private Optional<X509CRL> getDownloadedCrl(URI uri, X509Certificate certificate, X509Certificate issuer, Instant now) {
        downloadedCrls.values().removeIf(downloaded -> downloaded.isPastNextUpdateAt(now));
        DownloadedCrl cached = downloadedCrls.get(uri);
        boolean cachedIsUsable = cached != null && isUsableCrlFor(cached.crl, certificate, issuer, now);
        if (cachedIsUsable && !cached.isOlderThanMaxAgeAt(now)) {
            return Optional.of(cached.crl);
        }
        CrlLookup lookup = new CrlLookup(uri);
        try {
            X509CRL downloaded = lookup.executeUsing(client);
            if (isUsableCrlFor(downloaded, certificate, issuer, now)) {
                downloadedCrls.put(uri, new DownloadedCrl(downloaded, now));
                return Optional.of(downloaded);
            }
        } catch (RuntimeException e) {
            LOG.warn("Failed {} for issuer {}: {} '{}'", lookup, describe(issuer), e.getClass().getSimpleName(), e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getClass().getSimpleName() + ": '" + e.getMessage() + "'", e);
            }
        }
        if (cachedIsUsable) {
            LOG.warn("Using CRL from {} downloaded at {}, because a new CRL could not be downloaded", uri, cached.downloaded);
            return Optional.of(cached.crl);
        }
        return Optional.empty();
    }


    private static final class DownloadedCrl {
        final X509CRL crl;
        final Instant downloaded;

        DownloadedCrl(X509CRL crl, Instant downloaded) {
            this.crl = crl;
            this.downloaded = downloaded;
        }

        boolean isOlderThanMaxAgeAt(Instant instant) {
            return !instant.isBefore(downloaded.plus(MAX_AGE_OF_DOWNLOADED_CRL));
        }

        boolean isPastNextUpdateAt(Instant instant) {
            return crl.getNextUpdate() == null || !instant.isBefore(crl.getNextUpdate().toInstant());
        }
    }
}
