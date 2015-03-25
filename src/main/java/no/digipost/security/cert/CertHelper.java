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

import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.jce.provider.CertPathValidatorUtilities;

import java.security.SignatureException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.Set;

final class CertHelper extends CertPathValidatorUtilities {

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
		try {
	        TrustAnchor trustAnchor = findTrustAnchor(cert, trust);
			return Optional.ofNullable(trustAnchor).map(TrustAnchor::getTrustedCert);
        } catch (AnnotatedException e) {
	        throw new SignatureException("" + e.getMessage(), e);
        }
	}


	private CertHelper() {}
}