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
import no.digipost.security.ocsp.OcspResult;
import no.digipost.security.ocsp.OcspUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.time.temporal.ChronoUnit.HOURS;
import static java.time.temporal.ChronoUnit.MINUTES;
import static no.digipost.security.DigipostSecurity.describe;
import static no.digipost.security.cert.CertStatus.OK;
import static no.digipost.security.cert.CertStatus.REVOKED;
import static no.digipost.security.cert.CertStatus.UNDECIDED;
import static no.digipost.security.cert.OcspPolicy.NEVER_DO_OCSP_LOOKUP;
import static no.digipost.security.cert.RevocationReason.resolve;
import static no.digipost.security.cert.RevocationReason.unspecified;
import static org.bouncycastle.cert.ocsp.CertificateStatus.GOOD;


public class CertificateValidator {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateValidator.class);


    private final CertificateValidatorConfig config;
    private final CloseableHttpClient client;
    private final Map<X509Certificate, ResultWithTime> cache = new HashMap<>();
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
        this(config, trust, httpClient, Clock.systemUTC());
    }

    CertificateValidator(CertificateValidatorConfig config, Trust trust, CloseableHttpClient httpClient, Clock clock) {
        this.config = config;
        this.trust = trust;
        this.client = httpClient;
        this.clock = clock;
    }


    public CertStatus validateCert(Certificate certificate) {
        return validateCert(certificate, config);
    }

    private CertStatus validateCert(Certificate certificate, CertificateValidatorConfig config) {

        if (!(certificate instanceof X509Certificate)) {
            LOG.warn("Tried to validate a non-" + X509Certificate.class.getSimpleName() + ": " + certificate.getType() + "(" + certificate.getClass().getName() + ")");
            return CertStatus.UNTRUSTED;
        }

        X509Certificate x509Certificate = DigipostSecurity.requireX509(certificate);
        final ResultWithTime cachedResult;
        if (cache.containsKey(x509Certificate)) {
            cachedResult = cache.get(x509Certificate);
            if (!cachedResult.isExpiredAt(clock.instant()) || cachedResult.status == REVOKED) {
                return cachedResult.status;
            }
        } else {
            cachedResult = null;
        }

        ReviewedCertPath certPath = trust.resolveCertPath(x509Certificate);
        if (!certPath.isTrusted()) {
            return CertStatus.UNTRUSTED;
        }

        TrustedCertificateAndIssuer trustedCertificateAndIssuer = certPath.getTrustedCertificateAndIssuer();
        if (config.ocspPolicy.decideFor(trustedCertificateAndIssuer) == OcspDecision.LOOKUP_OCSP) {
            CertStatus ocspStatus = ocspLookup(trustedCertificateAndIssuer, config);
            if (ocspStatus != OK && config.allowsOcspResult(ocspStatus)) {
                LOG.info("Status {} for certificate {} is configured as {}", ocspStatus, describe(certificate), OK);
                ocspStatus = OK;
            }
            if (ocspStatus == UNDECIDED) {
                if (cachedResult != null && cachedResult.isValidAsStaleValueForFailedResolvingOfNewValue(clock.instant())) {
                    if (cachedResult.shouldLogIfUsedAsStaleValue(clock.instant())) {
                        LOG.error("OCSP older than 2 hours: {}", describe(x509Certificate));
                    }
                    cachedResult.setUnexpiredFrom(clock.instant());
                    return cachedResult.status;
                }
            }
            cache.put(x509Certificate, new ResultWithTime(clock.instant(), ocspStatus));
            return ocspStatus;
        } else {
            cache.put(x509Certificate, new ResultWithTime(clock.instant(), OK));
            return OK;
        }
    }

    private CertStatus ocspLookup(TrustedCertificateAndIssuer certificateAndIssuer, CertificateValidatorConfig config) {
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
                .map(result -> {
                    try (OcspResult ocspResult = result) {
                        if (!ocspResult.isOkResponse()) {
                            LOG.warn("Unexpected OCSP response ({}) for {}.", ocspResult.response.getStatusLine(), certificateAndIssuer);
                            return UNDECIDED;
                        }
                        BasicOCSPResp basix;
                        try {
                            basix = ocspResult.getResponseObject();
                        } catch (OCSPException | CertIOException | IllegalStateException e) {
                            LOG.warn("OCSP response for {}, error reading the response because: {} '{}'", certificateAndIssuer, e.getClass().getSimpleName(), e.getMessage());
                            return UNDECIDED;
                        }

                        if(basix == null) {
                            LOG.warn("OCSP response for {}, returned a null response, this could be a problem with the certificate issuer", certificateAndIssuer);
                            return UNDECIDED;
                        }

                        X509Certificate ocspSignatureValidationCertificate;
                        Optional<X509Certificate> ocspSigningCertificate = findOcspSigningCertificate(basix, config);
                        if (ocspSigningCertificate.isPresent()) {
                            ocspSignatureValidationCertificate = ocspSigningCertificate.get();
                            CertStatus certStatus = validateCert(ocspSignatureValidationCertificate, config.withOcspPolicy(NEVER_DO_OCSP_LOOKUP));
                            if (certStatus != OK) {
                                LOG.warn("OCSP signing certificate {} is not OK: '{}'", describe(ocspSignatureValidationCertificate), certStatus);
                                return certStatus;
                            }
                        } else {
                            ocspSignatureValidationCertificate = certificateAndIssuer.issuer;
                        }

                        if (!config.ocspSignatureValidator.isValidSignature(basix, ocspSignatureValidationCertificate)) {
                            LOG.warn("OCSP response for {} returnerte et svar som feilet signaturvalidering", certificateAndIssuer);
                            return UNDECIDED;
                        }

                        for (SingleResp cresp : basix.getResponses()) {
                            if (cresp.getCertStatus() != GOOD) {
                                if (cresp.getCertStatus() instanceof RevokedStatus) {
                                    RevokedStatus s = (RevokedStatus) cresp.getCertStatus();
                                    RevocationReason reason = Optional.of(s).filter(RevokedStatus::hasRevocationReason).map(r -> resolve(r.getRevocationReason())).orElse(unspecified);
                                    LOG.warn("OCSP response for {} returned status revoked: {}, reason: '{}'", certificateAndIssuer, s.getRevocationTime(), reason);
                                    return REVOKED;
                                } else {
                                    LOG.warn("OCSP response for {} returned status {}", certificateAndIssuer, cresp.getCertStatus().getClass().getSimpleName());
                                    return UNDECIDED;
                                }
                            }
                        }
                        LOG.debug("OCSP response for {} returned status GOOD", certificateAndIssuer);
                        return OK;
                    } catch (OCSPException | IOException e) {
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
