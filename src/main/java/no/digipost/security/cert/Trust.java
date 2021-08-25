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
import no.digipost.security.keystore.KeyStoreType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableMap;
import static java.util.Collections.unmodifiableSet;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;
import static java.util.stream.Stream.concat;
import static no.digipost.security.DigipostSecurity.PKIX;
import static no.digipost.security.DigipostSecurity.describe;

/**
 * The Trust contains the root certificates and any intermediate certificates you
 * choose to trust in your application. It can then be used to resolve
 * {@link #resolveCertPath(X509Certificate) the certificatation path} of a certificate,
 * and determined if it {@link ReviewedCertPath#isTrusted() is trusted} or not.
 */
public final class Trust {

    /**
     * Construct a Trust from the given trusted certificates.
     *
     * @param trustedCertificates all the certificates, both trust anchors and any
     *                            intermediate certificates issued from any of the trust anchors
     * @param clock the clock to use for asserting certificate validity
     * @return the Trust for the given certificates
     */
    public static Trust from(Clock clock, X509Certificate ... trustedCertificates) {
        return Trust.from(clock, Stream.of(trustedCertificates));
    }

    /**
     * Construct a Trust from the given trusted certificates.
     *
     * @param trustedCertificates all the certificates, both trust anchors and any
     *                            intermediate certificates issued from any of the trust anchors
     * @param clock the clock to use for asserting certificate validity
     * @return the Trust for the given certificates
     */
    public static Trust from(Clock clock, Stream<X509Certificate> trustedCertificates) {
        Map<TrustBasis, Set<X509Certificate>> grouped = trustedCertificates.collect(groupingBy(TrustBasis::determineFrom, toSet()));
        return new Trust(
                grouped.getOrDefault(TrustBasis.ANCHOR, emptySet()).stream(),
                grouped.getOrDefault(TrustBasis.DERIVED, emptySet()).stream(),
                clock);
    }

    /**
     * Merge two {@code Trust}s. The resulting trust will be the union of the given trusts.
     *
     * @param t1 the first trust
     * @param t2 the second trust
     *
     * @return the resulting trust from merging {@code t1} and {@code t2}
     */
    public static Trust merge(Trust t1, Trust t2) {
        if (!Objects.equals(t1.clock, t2.clock)) {
            throw new NonMatchingClocksException(t1.clock, t2.clock);
        }
        return new Trust(
                mergeMultimaps(t1.trustAnchorCerts, t2.trustAnchorCerts),
                mergeMultimaps(t1.trustedIntermediateCerts, t2.trustedIntermediateCerts),
                t1.clock);
    }

    private static <K, V> Map<K, Set<V>> mergeMultimaps(Map<K, Set<V>> m1, Map<K, Set<V>> m2) {
        Map<K, Set<V>> merged = new HashMap<>();
        for (Entry<K, Set<V>> m1Entry : m1.entrySet()) {
            K m1key = m1Entry.getKey();
            Set<V> union = new HashSet<>(m1Entry.getValue());
            union.addAll(m2.getOrDefault(m1key, emptySet()));
            merged.put(m1key, unmodifiableSet(union));
        }
        for (Entry<K, Set<V>> m2Entry : m2.entrySet()) {
            K m2Key = m2Entry.getKey();
            if (!merged.containsKey(m2Key)) {
                merged.put(m2Key, m2Entry.getValue());
            }
        }
        return unmodifiableMap(merged);
    }


    private enum TrustBasis {
        /**
         * The trust in a trust anchor is assumed, i.e. it is simply something
         * you decide to trust.
         */
        ANCHOR,

        /**
         * Derived trust must be traceable back to a trust anchor, e.g. a certificate
         * must be issued by a another already trusted certificate.
         */
        DERIVED;

        static TrustBasis determineFrom(X509Certificate cert) {
            return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()) ? TrustBasis.ANCHOR : TrustBasis.DERIVED;
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(Trust.class);

    private final Map<X500Principal, Set<X509Certificate>> trustAnchorCerts;
    private final Map<X500Principal, Set<X509Certificate>> trustedIntermediateCerts;
    final Clock clock;

    public Trust(Stream<X509Certificate> trustAnchorCertificates, Stream<X509Certificate> intermediateCertificates) {
        this(trustAnchorCertificates, intermediateCertificates, Clock.systemDefaultZone());
    }

    public Trust(Stream<X509Certificate> trustAnchorCertificates, Stream<X509Certificate> intermediateCertificates, Clock clock) {
        this(
                unmodifiableMap(trustAnchorCertificates.collect(groupingBy(X509Certificate::getSubjectX500Principal, toSet()))),
                unmodifiableMap(intermediateCertificates.collect(groupingBy(X509Certificate::getSubjectX500Principal, toSet()))),
                clock);
    }

    private Trust(Map<X500Principal, Set<X509Certificate>> trustAnchorCerts, Map<X500Principal, Set<X509Certificate>> trustedIntermediateCerts, Clock clock) {
        this.trustAnchorCerts = requireNonNull(trustAnchorCerts, "trust anchor certificates");
        this.trustedIntermediateCerts = requireNonNull(trustedIntermediateCerts, "intermediate certificates");
        this.clock = requireNonNull(clock, "clock");
        validate();
    }


    private void validate() {
        List<X509Certificate> intermediateCertsWithoutAnchor = trustedIntermediateCerts
            .values().stream().flatMap(Set::stream)
            .filter(cert -> !trustAnchorCerts.containsKey(cert.getIssuerX500Principal()))
            .collect(toList());
        if (!intermediateCertsWithoutAnchor.isEmpty()) {
            throw new MissingTrustAnchorException(intermediateCertsWithoutAnchor);
        }
    }

    /**
     * Resolve the certificate path of an X.509 certificate.
     *
     * @param certificate the certificate to resolve the whole path for.
     * @return the certificate path, wrapped as a {@link ReviewedCertPath}, with methods
     *         to determine if it {@link ReviewedCertPath#isTrusted() is trusted}, and to retrieve the
     *         {@link ReviewedCertPath#getTrustedCertificateAndIssuer() trusted certificate and its issuer}.
     */
    public ReviewedCertPath resolveCertPath(X509Certificate certificate) {
        try {
            CollectionCertStoreParameters certStoreParams = new CollectionCertStoreParameters(
                    getTrustAnchorsAndAnyIntermediateCertificatesFor(certificate.getIssuerX500Principal()).collect(toSet()));

            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setCertificate(certificate);
            certSelector.setSubject(certificate.getSubjectX500Principal());
            certSelector.setCertificateValid(Date.from(clock.instant()));

            CertStore certStore = CertStore.getInstance("Collection", certStoreParams);
            PKIXBuilderParameters params = new PKIXBuilderParameters(getTrustAnchors(), certSelector);
            params.addCertStore(certStore);
            params.setSigProvider(DigipostSecurity.PROVIDER_NAME);
            params.setRevocationEnabled(false);
            params.setDate(Date.from(clock.instant()));
            CertPath certpath = CertPathBuilder.getInstance(PKIX).build(params).getCertPath();
            if (certpath.getCertificates().size() > 1) {
                return new ReviewedCertPath(certpath, this::trusts);
            } else {
                // Use alternative method to create certpath. This is used for non-buypass certificates, for example
                // certificates issues by Digipost's own CA-certificate
                CertificateFactory cf = DigipostSecurity.getX509CertificateFactory();
                Optional<X509Certificate> issuer = CertHelper.findTrustAnchorCert(certificate, getTrustAnchors());
                return new ReviewedCertPath(cf.generateCertPath(concat(Stream.of(certificate), issuer.map(Stream::of).orElse(Stream.empty())).collect(toList())), path -> issuer.isPresent());
            }

        } catch (GeneralSecurityException e) {
            LOG.warn("Error generating cert path for certificate, because the issuer is not trusted. {}: {}. certificate: {}",
                    e.getClass().getSimpleName(), e.getMessage(), describe(certificate));
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getClass().getSimpleName() + ": '" + e.getMessage() + "'", e);
            }
            return new ReviewedCertPath(e);
        }
    }


    /**
     * Determine if a certificate path is trusted or not
     *
     * @return <code>true</code> if the path is trusted, <code>false</code> otherwise.
     */
    public boolean trusts(CertPath certPath) {
        try {
            Set<TrustAnchor> trustAnchors = getTrustAnchors();
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setSigProvider(DigipostSecurity.PROVIDER_NAME);
            params.setRevocationEnabled(false);
            params.setDate(Date.from(clock.instant()));
            CertPathValidator.getInstance(PKIX).validate(certPath, params);
            return true;
        } catch (CertPathValidatorException e) {
            return false;
        } catch (GeneralSecurityException e) {
            throw new DigipostSecurityException(e);
        }
    }


    /**
     * @return the {@link TrustAnchor}s of this {@code Trust}
     *
     * @see #getTrustAnchorCertificates()
     */
    public Set<TrustAnchor> getTrustAnchors() {
        return getTrustAnchorCertificates().stream().map(c -> new TrustAnchor(c, null)).collect(toSet());
    }


    /**
     * A trust anchor is the authoritative entity for which trust is assumed
     * and not derived, i.e. the root certificates from which the whole chain of trust is derived.
     *
     * @return the {@link X509Certificate trust anchor certificates} of this {@code Trust}
     */
    public Set<X509Certificate> getTrustAnchorCertificates() {
        return trustAnchorCerts.values().stream().flatMap(Set::stream).collect(toSet());
    }


    /**
     * @return a {@link KeyStore} populated with the
     *         {@link #getTrustAnchorCertificates() trust anchor certificates}
     *         of this {@code Trust}
     */
    public KeyStore getTrustAnchorsKeyStore() {
        return KeyStoreType.JCEKS.newKeyStore().containing(this.getTrustAnchorCertificates()).withNoPassword();
    }


    public Map<X500Principal, Set<X509Certificate>> getTrustedIntermediateCertificates() {
        return trustedIntermediateCerts;
    }


    Stream<X509Certificate> getTrustAnchorsAndAnyIntermediateCertificatesFor(X500Principal principal) {
        return concat(getTrustAnchorCertificates().stream(), getTrustedIntermediateCertificates().getOrDefault(principal, emptySet()).stream());
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof Trust) {
            Trust that = (Trust) other;
            return Objects.equals(this.clock, that.clock)
                    && Objects.equals(this.trustAnchorCerts, that.trustAnchorCerts)
                    && Objects.equals(this.trustedIntermediateCerts, that.trustedIntermediateCerts);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(clock, trustAnchorCerts, trustedIntermediateCerts);
    }


}
