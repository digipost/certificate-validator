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
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
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
    private final Map<List<Certificate>, ResolvedCertPath> resolvedCertPaths = new ConcurrentHashMap<>();
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
     * Validate a leaf certificate, using the given chain to build the path up to a trust anchor.
     * The chain is not trusted in itself, and may be in any order and include unrelated certificates.
     * Supplied intermediates are checked with CRL, falling back to OCSP if allowed by the OCSP policy.
     *
     * @param leaf the certificate to validate
     * @param chain additional certificates, typically intermediates sent along with {@code leaf}
     * @return the status of the {@code leaf} certificate
     */
    public CertStatus validateCert(Certificate leaf, Collection<? extends Certificate> chain) {
        return validateCert(leaf, chain, config);
    }

    /**
     * Validate a certificate chain where the first certificate is the leaf, as sent in TLS.
     * See {@link #validateCert(Certificate, Collection)}.
     *
     * @param chain the leaf certificate, followed by intermediate certificates
     * @return the status of the leaf certificate, or {@link CertStatus#UNTRUSTED} if the chain is empty
     */
    public CertStatus validateCertChain(List<? extends Certificate> chain) {
        if (chain.isEmpty()) {
            LOG.debug("Tried to validate an empty certificate chain");
            return CertStatus.UNTRUSTED;
        }
        return validateCert(chain.get(0), chain, config);
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

        ReviewedCertPath certPath = resolveCertPath(x509Certificate, chain);
        if (!certPath.isTrusted()) {
            return CertStatus.UNTRUSTED;
        }

        // Keyed on the trusted path, so extra certificates in the chain can not bypass the cache
        return cached(cache, certPath.getTrustedPath(), x509Certificate, config, () -> {
            // Intermediates first, so their status is cached for the OCSP signer of the leaf.
            // OCSP signers are validated with only the trusted path, not with other certificates from the chain.
            List<? extends Certificate> trustedPath = certPath.getTrustedPath().getCertificates();
            CertStatus intermediatesStatus = checkSuppliedIntermediateCertificates(certPath.getTrustedPath(), config);
            CertStatus certificateStatus = checkCertificate(certPath.getTrustedCertificateAndIssuer(), trustedPath, config);
            if (certificateStatus == REVOKED) {
                revokedCertificates.add(x509Certificate);
            }
            return mostSevere(intermediatesStatus, certificateStatus);
        });
    }

    /**
     * Resolve the cert path, reusing a recently resolved trusted path for the same certificate and chain.
     * A chain with other certificates is resolved again, and if it results in the same trusted path, the
     * status is still found in the cache keyed on the trusted path.
     */
    private ReviewedCertPath resolveCertPath(X509Certificate certificate, Collection<? extends Certificate> chain) {
        List<Certificate> key = new ArrayList<>(chain.size() + 1);
        key.add(certificate);
        key.addAll(chain);
        Instant now = clock.instant();
        ResolvedCertPath resolved = resolvedCertPaths.get(key);
        if (resolved != null && !resolved.isExpiredAt(now)) {
            return resolved.certPath;
        }

        ReviewedCertPath certPath = trust.resolveCertPath(certificate, chain);
        if (certPath.isTrusted()) {
            if (resolvedCertPaths.size() >= MAX_RESOLVED_CERT_PATHS) {
                resolvedCertPaths.values().removeIf(r -> r.isExpiredAt(now));
            }
            if (resolvedCertPaths.size() < MAX_RESOLVED_CERT_PATHS) {
                resolvedCertPaths.put(key, new ResolvedCertPath(certPath, now));
            }
        }
        return certPath;
    }

    private <K> CertStatus cached(Map<K, ResultWithTime> cache, K key, X509Certificate certificate, CertificateValidatorConfig config, Supplier<CertStatus> resolveStatus) {
        final ResultWithTime cachedResult = cache.get(key);
        if (cachedResult != null && (!cachedResult.isExpiredAt(clock.instant()) || cachedResult.status == REVOKED)) {
            return cachedResult.status;
        }

        CertStatus status = resolveStatus.get();
        if (config.ocspPolicy != this.config.ocspPolicy) {
            // Resolved with another OCSP policy than this validator's, i.e. for an OCSP signing certificate,
            // and must not be reused when validating with this validator's OCSP policy.
            return status;
        }

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
     * Check revocation of supplied intermediate certificates which are not already in the {@link Trust}.
     */
    private CertStatus checkSuppliedIntermediateCertificates(CertPath path, CertificateValidatorConfig config) {
        List<X509Certificate> certificates = asStream(path).collect(toList());
        Set<X509Certificate> alreadyTrusted = new HashSet<>(trust.getTrustAnchorCertificates());
        trust.getTrustedIntermediateCertificates().values().forEach(alreadyTrusted::addAll);

        CertStatus result = OK;
        // From the trust anchor towards the leaf, so the status of an intermediate is cached
        // before it is needed to validate the OCSP signer of the intermediate below it.
        for (int i = certificates.size() - 1; i >= 1; i--) {
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
                    .map(iss -> cached(intermediateCache, asList(intermediate, iss), intermediate, config, () -> revocationStatus(intermediate, iss, certificates, config)))
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
                        if (ocspSigningCertificate.isPresent() && !ocspSigningCertificate.get().equals(certificateAndIssuer.issuer)) {
                            ocspSignatureValidationCertificate = ocspSigningCertificate.get();
                            if (!isAuthorizedOcspSigner(ocspSignatureValidationCertificate, certificateAndIssuer.issuer)) {
                                LOG.warn("OCSP signing certificate is not authorized to sign OCSP responses for {}: {}", certificateAndIssuer, describe(ocspSignatureValidationCertificate));
                                return UNDECIDED;
                            }
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

    /**
     * A delegated OCSP signing certificate must be issued directly by the issuer of the certificate
     * the OCSP response is for, and have the OCSP signing extended key usage (RFC 6960 4.2.2.2).
     */
    private static boolean isAuthorizedOcspSigner(X509Certificate ocspSigningCertificate, X509Certificate issuer) {
        try {
            List<String> extendedKeyUsage = ocspSigningCertificate.getExtendedKeyUsage();
            if (extendedKeyUsage == null || !extendedKeyUsage.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
                return false;
            }
            if (!ocspSigningCertificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                return false;
            }
            ocspSigningCertificate.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            LOG.warn("OCSP signing certificate {} is not issued by {}: {} '{}'", describe(ocspSigningCertificate), describe(issuer), e.getClass().getSimpleName(), e.getMessage());
            return false;
        }
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



    /**
     * Bounds the memory used for resolved cert paths, as the supplied chains are not trusted.
     */
    private static final int MAX_RESOLVED_CERT_PATHS = 10_000;

    private static final class ResolvedCertPath {
        final ReviewedCertPath certPath;
        private final Instant expires;

        ResolvedCertPath(ReviewedCertPath certPath, Instant resolved) {
            this.certPath = certPath;
            this.expires = resolved.plus(5, MINUTES);
        }

        boolean isExpiredAt(Instant instant) {
            return !instant.isBefore(expires);
        }
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
