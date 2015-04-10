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

import javax.security.auth.x500.X500Principal;

import java.io.IOException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.Set;

import static java.util.Optional.empty;


final class CertHelper {

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
	static Optional<X509Certificate> findTrustAchorCert(final X509Certificate cert, final Set<TrustAnchor> trust) throws SignatureException {
        return findTrustAnchor(cert, trust).map(TrustAnchor::getTrustedCert);
	}



    /**
     * Code based on protected method findTrustAnchor in {@link CertPathValidatorUtilities}
     */
    static Optional<TrustAnchor> findTrustAnchor(X509Certificate cert, Set<TrustAnchor> trustAnchors) throws SignatureException {

    	PublicKey trustPublicKey = null;
        X509CertSelector certSelectX509 = new X509CertSelector();
        X500Principal certIssuer = cert.getIssuerX500Principal();

        try {
            certSelectX509.setSubject(certIssuer.getEncoded());
        } catch (IOException ex) {
            throw new SignatureException("Cannot set subject search criteria for trust anchor.", ex);
        }

        for (TrustAnchor trust : trustAnchors) {

            if (trust.getTrustedCert() != null) {
                if (certSelectX509.match(trust.getTrustedCert())) {
                    trustPublicKey = trust.getTrustedCert().getPublicKey();
                }
            } else if (trust.getCAName() != null && trust.getCAPublicKey() != null) {
                try {
                    X500Principal caName = new X500Principal(trust.getCAName());
                    if (certIssuer.equals(caName)) {
                        trustPublicKey = trust.getCAPublicKey();
                    }
                } catch (IllegalArgumentException ex) {
                	continue;
                }
            }

            if (trustPublicKey != null) {
                try {
                    cert.verify(trustPublicKey);
                    return Optional.of(trust);
                } catch (Exception ex) {
                	throw new SignatureException("TrustAnchor found but certificate validation failed.", ex);
                }
            }
        }
        return empty();
    }



	private CertHelper() {}
}