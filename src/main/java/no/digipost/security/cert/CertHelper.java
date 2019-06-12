/**
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

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;

import java.io.IOException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Optional.empty;
import static no.digipost.security.DigipostSecurity.describe;


final class CertHelper {

    private static final Logger LOG = LoggerFactory.getLogger(OcspPolicy.class);

    /**
     * Search the given Set of Trust Anchors for one that is the issuer of the
     * given X509 certificate. Uses the default provider for signature verification.
     *
     *
     * @param cert the certificate to find the issuer for
     * @param trust the Trust Anchors
     *
     * @return the found issuer certificate, or <code>{@link Optional#empty()}</code> if no was found.
     *
     * @throws SignatureException if a TrustAnchor was found but the signature verification on the given certificate has thrown an exception
     *                            (as per documentation of {@link CertPathValidatorUtilities#findTrustAnchor(X509Certificate, Set)}).
     */
    static Optional<X509Certificate> findTrustAnchorCert(final X509Certificate cert, final Set<TrustAnchor> trust) throws SignatureException {
        return findTrustAnchor(cert, trust).map(TrustAnchor::getTrustedCert);
    }



    /**
     * Code based on protected method findTrustAnchor in {@link CertPathValidatorUtilities}
     */
    static Optional<TrustAnchor> findTrustAnchor(X509Certificate cert, Set<TrustAnchor> trustAnchors) throws SignatureException {

        X509CertSelector certSelectX509 = new X509CertSelector();
        X500Principal certIssuer = cert.getIssuerX500Principal();

        try {
            certSelectX509.setSubject(certIssuer.getEncoded());
        } catch (IOException ex) {
            throw new SignatureException("Cannot set subject search criteria for trust anchor.", ex);
        }

        SignatureException certVerificationFailure = null;
        for (TrustAnchor trusted : trustAnchors) {

            PublicKey trustPublicKey = null;
            if (trusted.getTrustedCert() != null) {
                if (certSelectX509.match(trusted.getTrustedCert())) {
                    trustPublicKey = trusted.getTrustedCert().getPublicKey();
                }
            } else if (trusted.getCA() != null && trusted.getCAPublicKey() != null) {
                X500Principal caName = trusted.getCA();
                if (certIssuer.equals(caName)) {
                    trustPublicKey = trusted.getCAPublicKey();
                }
            }

            if (trustPublicKey != null) {
                try {
                    cert.verify(trustPublicKey);
                    return Optional.of(trusted);
                } catch (Exception ex) {
                    if (certVerificationFailure == null) {
                        certVerificationFailure = new SignatureException("TrustAnchor found, but certificate validation for " + describe(cert) + " failed", ex);
                    } else {
                        certVerificationFailure.addSuppressed(ex);
                    }
                }
            }
        }

        if (certVerificationFailure != null) {
            throw certVerificationFailure;
        } else {
            return empty();
        }
    }


    static Stream<String> getOrganizationUnits(X509Certificate cert) {
        X509CertificateHolder bouncyCastleX509cert;
        try {
            bouncyCastleX509cert = new JcaX509CertificateHolder(cert);
        } catch (CertificateEncodingException e) {
            LOG.warn(
                    "Unable to resolve organizational units (OU=xyz) from " + describe(cert) +
                    ", because " + e.getClass().getSimpleName() + ": '" + e.getMessage() + "'", e);
            return Stream.empty();
        }
        return Stream.of(bouncyCastleX509cert.getSubject().getRDNs(BCStyle.OU))
                .map(RDN::getTypesAndValues)
                .flatMap(Stream::of)
                .map(AttributeTypeAndValue::getValue)
                .map(IETFUtils::valueToString);
    }


    private CertHelper() {}

}
