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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableMap;
import static java.util.Collections.unmodifiableSet;
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
public class Trust {

    private static final Logger LOG = LoggerFactory.getLogger(Trust.class);

    private final Set<X509Certificate> trustedCerts;
    private final Map<X500Principal, List<X509Certificate>> trustedIntermediateCerts;
    private final Clock clock;

    public Trust(Stream<X509Certificate> rootCertificates, Stream<X509Certificate> intermediateCertificates) {
        this(rootCertificates, intermediateCertificates, Clock.systemDefaultZone());
    }

    public Trust(Stream<X509Certificate> rootCertificates, Stream<X509Certificate> intermediateCertificates, Clock clock) {
        this.clock = clock;
        this.trustedCerts = unmodifiableSet(rootCertificates.collect(toSet()));
        this.trustedIntermediateCerts = unmodifiableMap(intermediateCertificates.collect(groupingBy(X509Certificate::getSubjectX500Principal)));
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
    public boolean trusts(final CertPath certPath) {
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


    public Set<TrustAnchor> getTrustAnchors() {
        return getTrustAnchorCertificates().stream().map(c -> new TrustAnchor(c, null)).collect(toSet());
    }

    public Set<X509Certificate> getTrustAnchorCertificates() {
        return trustedCerts;
    }

    public KeyStore getTrustAnchorsKeyStore() {
        return KeyStoreType.JCEKS.newKeyStore().containing(this.getTrustAnchorCertificates()).withNoPassword();
    }

    public Map<X500Principal, List<X509Certificate>> getTrustedIntermediateCertificates() {
        return trustedIntermediateCerts;
    }

    Stream<X509Certificate> getTrustAnchorsAndAnyIntermediateCertificatesFor(X500Principal principal) {
        return concat(getTrustAnchorCertificates().stream(), getTrustedIntermediateCertificates().getOrDefault(principal, emptyList()).stream());
    }

}
