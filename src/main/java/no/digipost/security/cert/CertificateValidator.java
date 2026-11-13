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

import no.digipost.security.DigipostSecurity;
import no.digipost.security.DigipostSecurityException;
import no.digipost.security.ocsp.OcspLookup;
import no.digipost.security.ocsp.OcspUtils;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import static java.time.temporal.ChronoUnit.HOURS;
import static java.time.temporal.ChronoUnit.MINUTES;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;
import static no.digipost.security.DigipostSecurity.asStream;
import static no.digipost.security.DigipostSecurity.describe;
import static no.digipost.security.cert.CertStatus.OK;
import static no.digipost.security.cert.CertStatus.REVOKED;
import static no.digipost.security.cert.CertStatus.UNDECIDED;
import static no.digipost.security.cert.CertStatus.UNTRUSTED;
import static no.digipost.security.cert.OcspPolicy.NEVER_DO_OCSP_LOOKUP;
import static no.digipost.security.cert.RevocationReason.resolve;
import static no.digipost.security.cert.RevocationReason.unspecified;
import static org.bouncycastle.cert.ocsp.CertificateStatus.GOOD;


public class CertificateValidator {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateValidator.class);


    private final CertificateValidatorConfig config;
    private final CloseableHttpClient client;
    private final Map<CertPath, ResultWithTime> cache = new HashMap<>();
    private final Set<X509Certificate> revokedCertificates = ConcurrentHashMap.newKeySet();
    private final Map<List<X509Certificate>, ResultWithTime> intermediateCache = new ConcurrentHashMap<>();
    private final CrlChecker crlChecker;
    private final Trust trust;
    private final Clock clock;




    /**
     * Creates a validator using the {@link CertificateValidatorConfig#MOST_STRICT most strict}
     * settings.
     */
    public CertificateValidator(Trust trust, CloseableHttpClient httpClient) {
        this(CertificateValidatorConfig.MOST_STRICT, trust, httpClient);
    }

    public CertificateValidator(CertificateValidatorConfig config, Trust trust, CloseableHttpClient httpClient) {
        this.config = config;
        this.trust = trust;
        this.client = httpClient;
        this.clock = trust.clock;
        this.crlChecker = new CrlChecker(httpClient, clock);
    }


    public CertStatus validateCert(Certificate certificate) {
        return validateCert(certificate, emptyList(), config);
    }

    /**
     * Validate a leaf certificate, using the given chain to build the certificate path up to a trust anchor.
     * The chain is not trusted in itself. Intermediate certificates from the chain are checked for revocation
     * using CRL (from the {@link CertificateValidatorConfig#withCrlProvider(no.digipost.security.crl.CrlProvider) CRL provider}
     * or the certificate's CRL distribution points), falling back to OCSP if allowed by the
     * OCSP policy. If the status can not be
     * determined, the result is {@link CertStatus#UNDECIDED}, unless allowed by
     * {@link CertificateValidatorConfig#allowOcspResults(CertStatus...)}.
     * <p>
     * The chain is only used as candidates for building the path, so it may be given as received, e.g. from TLS
     * or a signature: in any order, including the {@code leaf} itself, duplicates or unrelated certificates.
     * Certificates in the chain which are not part of the resolved path are ignored.
     *
     * @param leaf the certificate to validate
     * @param chain additional certificates, typically intermediate certificates sent along with {@code leaf}
     * @return the status of the {@code leaf} certificate
     *
     * @see Trust#resolveCertPath(X509Certificate, Collection)
     */
    public CertStatus validateCert(Certificate leaf, Collection<? extends Certificate> chain) {
        return validateCert(leaf, chain, config);
    }

    private CertStatus validateCert(Certificate certificate, Collection<? extends Certificate> chain, CertificateValidatorConfig config) {

        if (!(certificate instanceof X509Certificate)) {
            LOG.warn("Tried to validate a non-" + X509Certificate.class.getSimpleName() + ": " + certificate.getType() + "(" + certificate.getClass().getName() + ")");
            return CertStatus.UNTRUSTED;
        }

        X509Certificate x509Certificate = DigipostSecurity.requireX509(certificate);
        if (revokedCertificates.contains(x509Certificate)) {
            return REVOKED;
        }

        ReviewedCertPath certPath = trust.resolveCertPath(x509Certificate, chain);
        if (!certPath.isTrusted()) {
            return CertStatus.UNTRUSTED;
        }

        // Keyed on the resolved trusted path, not the supplied (untrusted) chain, so that
        // extraneous certificates in the chain can not bypass cached results.
        return cached(cache, certPath.getTrustedPath(), x509Certificate, () -> {
            // Intermediates first, so their status is cached for the OCSP signer of the leaf
            CertStatus intermediatesStatus = checkSuppliedIntermediateCertificates(certPath.getTrustedPath(), chain, config);
            CertStatus certificateStatus = checkCertificate(certPath.getTrustedCertificateAndIssuer(), chain, config);
            if (certificateStatus == REVOKED) {
                revokedCertificates.add(x509Certificate);
            }
            return mostSevere(intermediatesStatus, certificateStatus);
        });
    }

    private <K> CertStatus cached(Map<K, ResultWithTime> cache, K key, X509Certificate certificate, Supplier<CertStatus> resolveStatus) {
        final ResultWithTime cachedResult = cache.get(key);
        if (cachedResult != null && (!cachedResult.isExpiredAt(clock.instant()) || cachedResult.status == REVOKED)) {
            return cachedResult.status;
        }

        CertStatus status = resolveStatus.get();

        if (status == UNDECIDED && cachedResult != null && cachedResult.isValidAsStaleValueForFailedResolvingOfNewValue(clock.instant())) {
            if (cachedResult.shouldLogIfUsedAsStaleValue(clock.instant())) {
                LOG.error("Revocation status older than 2 hours: {}", describe(certificate));
            }
            cachedResult.setUnexpiredFrom(clock.instant());
            return cachedResult.status;
        }
        cache.put(key, new ResultWithTime(clock.instant(), status));
        return status;
    }

    private CertStatus checkCertificate(TrustedCertificateAndIssuer trustedCertificateAndIssuer, Collection<? extends Certificate> chain, CertificateValidatorConfig config) {
        if (config.ocspPolicy.decideFor(trustedCertificateAndIssuer) != OcspDecision.LOOKUP_OCSP) {
            return OK;
        }
        CertStatus ocspStatus = ocspLookup(trustedCertificateAndIssuer, chain, config);
        if (ocspStatus != OK && config.allowsOcspResult(ocspStatus)) {
            LOG.info("Status {} for certificate {} is configured as {}", ocspStatus, describe(trustedCertificateAndIssuer.certificate), OK);
            return OK;
        }
        return ocspStatus;
    }

    /**
     * Check revocation status of the intermediate certificates in the path which are not already
     * part of the {@link Trust}, i.e. intermediate certificates supplied with the certificate to validate.
     * CRL is used if available, either from the {@link CertificateValidatorConfig#withCrlProvider(no.digipost.security.crl.CrlProvider) CRL provider}
     * or the CRL distribution points of the certificate, and otherwise OCSP.
     */
    private CertStatus checkSuppliedIntermediateCertificates(CertPath path, Collection<? extends Certificate> chain, CertificateValidatorConfig config) {
        List<X509Certificate> certificates = asStream(path).collect(toList());
        Set<X509Certificate> alreadyTrusted = new HashSet<>(trust.getTrustAnchorCertificates());
        trust.getTrustedIntermediateCertificates().values().forEach(alreadyTrusted::addAll);

        CertStatus result = OK;
        for (int i = 1; i < certificates.size(); i++) {
            X509Certificate intermediate = certificates.get(i);
            if (alreadyTrusted.contains(intermediate)) {
                continue;
            }
            Optional<X509Certificate> issuer;
            if (i + 1 < certificates.size()) {
                issuer = Optional.of(certificates.get(i + 1));
            } else {
                try {
                    issuer = CertHelper.findTrustAnchorCert(intermediate, trust.getTrustAnchors());
                } catch (SignatureException e) {
                    LOG.warn("Unable to find issuer of intermediate certificate {}: {} '{}'", describe(intermediate), e.getClass().getSimpleName(), e.getMessage());
                    issuer = Optional.empty();
                }
            }
            CertStatus status = issuer
                    .map(iss -> cached(intermediateCache, asList(intermediate, iss), intermediate, () -> revocationStatus(intermediate, iss, chain, config)))
                    .orElse(UNDECIDED);
            if (status != OK && config.allowsOcspResult(status)) {
                LOG.info("Status {} for intermediate certificate {} is configured as {}", status, describe(intermediate), OK);
                status = OK;
            }
            result = mostSevere(result, status);
        }
        return result;
    }

    private CertStatus revocationStatus(X509Certificate certificate, X509Certificate issuer, Collection<? extends Certificate> chain, CertificateValidatorConfig config) {
        Optional<CertStatus> crlStatus = crlChecker.check(certificate, issuer, config.crlProvider);
        if (crlStatus.isPresent()) {
            return crlStatus.get();
        }
        TrustedCertificateAndIssuer certificateAndIssuer = new TrustedCertificateAndIssuer(certificate, issuer);
        if (config.ocspPolicy.decideFor(certificateAndIssuer) != OcspDecision.LOOKUP_OCSP) {
            // Also bounds recursion: OCSP signing certificates are validated with NEVER_DO_OCSP_LOOKUP
            LOG.warn("Unable to determine revocation status of intermediate certificate {}, no usable CRL and OCSP lookup is not allowed by policy", describe(certificate));
            return UNDECIDED;
        }
        if (certificateAndIssuer.ocspLookupRequest.isPresent()) {
            return ocspLookup(certificateAndIssuer, chain, config);
        }
        LOG.warn("Unable to determine revocation status of intermediate certificate {}, no usable CRL or OCSP responder", describe(certificate));
        return UNDECIDED;
    }

    private static CertStatus mostSevere(CertStatus s1, CertStatus s2) {
        return SEVERITY.indexOf(s1) >= SEVERITY.indexOf(s2) ? s1 : s2;
    }

    private static final List<CertStatus> SEVERITY = asList(OK, UNDECIDED, UNTRUSTED, REVOKED);

    private CertStatus ocspLookup(TrustedCertificateAndIssuer certificateAndIssuer, Collection<? extends Certificate> chain, CertificateValidatorConfig config) {
        return certificateAndIssuer
                .ocspLookupRequest
                .map(OcspLookup::new)
                .flatMap(lookup -> {
                    try {
                        return Optional.of(lookup.executeUsing(client));
                    } catch (RuntimeException e) {
                        LOG.warn("Failed {} for {}: {} '{}'", lookup, certificateAndIssuer, e.getClass().getSimpleName(), e.getMessage());
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(e.getClass().getSimpleName() + ": '" + e.getMessage() + "'", e);
                        }
                        return Optional.empty();
                    }
                })
                .map(ocspResult -> {
                    try {
                        if (!ocspResult.isOkResponse()) {
                            LOG.warn("Unexpected {} for {}.", ocspResult, certificateAndIssuer);
                            return UNDECIDED;
                        }
                        BasicOCSPResp basix;
                        try {
                            basix = ocspResult.getResponseObject();
                        } catch (DigipostSecurityException e) {
                            LOG.warn("OCSP response for {}, error reading the response because {} '{}'", certificateAndIssuer, e.getClass().getSimpleName(), e.getMessage());
                            return UNDECIDED;
                        }

                        X509Certificate ocspSignatureValidationCertificate;
                        Optional<X509Certificate> ocspSigningCertificate = findOcspSigningCertificate(basix, config);
                        if (ocspSigningCertificate.isPresent()) {
                            ocspSignatureValidationCertificate = ocspSigningCertificate.get();
                            CertStatus certStatus = validateCert(ocspSignatureValidationCertificate, chain, config.withOcspPolicy(NEVER_DO_OCSP_LOOKUP));
                            if (certStatus != OK) {
                                LOG.warn("OCSP signing certificate is '{}': {}", certStatus, describe(ocspSignatureValidationCertificate));
                                return certStatus;
                            }
                        } else {
                            ocspSignatureValidationCertificate = certificateAndIssuer.issuer;
                        }

                        if (!config.ocspSignatureValidator.isValidSignature(basix, ocspSignatureValidationCertificate)) {
                            LOG.warn("OCSP response for {} failed signature validation", certificateAndIssuer);
                            return UNDECIDED;
                        }

                        for (SingleResp cresp : basix.getResponses()) {
                            if (cresp.getCertStatus() != GOOD) {
                                if (cresp.getCertStatus() instanceof RevokedStatus) {
                                    RevokedStatus s = (RevokedStatus) cresp.getCertStatus();
                                    RevocationReason reason = Optional.of(s).filter(RevokedStatus::hasRevocationReason).map(r -> resolve(r.getRevocationReason())).orElse(unspecified);
                                    LOG.info("OCSP response for {} returned status revoked: {}, reason: '{}'", certificateAndIssuer, s.getRevocationTime(), reason);
                                    return REVOKED;
                                } else {
                                    LOG.info("OCSP response for {} returned status {}", certificateAndIssuer, cresp.getCertStatus().getClass().getSimpleName());
                                    return UNDECIDED;
                                }
                            }
                        }
                        LOG.debug("OCSP response for {} returned status GOOD", certificateAndIssuer);
                        return OK;
                    } catch (OCSPException e) {
                        throw new DigipostSecurityException(e);
                    }
                })
                .orElse(UNDECIDED);

    }

    private static Optional<X509Certificate> findOcspSigningCertificate(BasicOCSPResp basix, CertificateValidatorConfig config) {
        if (config.ignoreCustomSigningCertificatesInOcspResponses) {
            return Optional.empty();
        }
        Optional<X509Certificate> ocspSigningCertificate;
        try {
            ocspSigningCertificate = OcspUtils.findOscpSigningCertificate(basix);
        } catch (Exception e) {
            LOG.warn("Unexpected error while loooking for OCSP signing certificate in OCSP-response. {}: '{}'", e.getClass().getSimpleName(), e.getMessage(), e);
            ocspSigningCertificate = Optional.empty();
        }
        return ocspSigningCertificate;
    }



    private static class ResultWithTime {
        public final CertStatus status;

        private final Instant reallyExpires;
        private final Instant warnAfter;
        private Instant expires;

        public ResultWithTime(final Instant validated, final CertStatus status) {
            this.status = status;
            if (status == UNDECIDED) {
                expires = validated.plus(1, MINUTES);
                reallyExpires = expires;
                warnAfter = expires;
            } else {
                expires = validated.plus(5, MINUTES);
                reallyExpires = validated.plus(48, HOURS);
                warnAfter = validated.plus(2, HOURS);
            }
        }

        void setUnexpiredFrom(Instant instant) {
            expires = instant.plus(1, MINUTES);
        }

        boolean isExpiredAt(Instant instant) {
            return !instant.isBefore(expires);
        }

        boolean isValidAsStaleValueForFailedResolvingOfNewValue(Instant instant) {
            return instant.isBefore(reallyExpires);
        }

        boolean shouldLogIfUsedAsStaleValue(Instant instant) {
            return instant.isAfter(warnAfter);
        }
    }
}
