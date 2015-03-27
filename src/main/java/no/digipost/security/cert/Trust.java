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

import no.digipost.security.DigipostSecurity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Collections.*;
import static java.util.stream.Collectors.*;
import static java.util.stream.Stream.concat;
import static no.digipost.function.Functions.asUnchecked;
import static no.digipost.function.Functions.exceptionNameAndMessage;
import static no.digipost.security.DigipostSecurity.*;

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

	public Trust(Stream<X509Certificate> rootCertificates, Stream<X509Certificate> intermediateCertificates) {
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
			CollectionCertStoreParameters certStoreParams = new CollectionCertStoreParameters(getAllTrustedCertificatesFor(certificate.getIssuerX500Principal()).collect(toSet()));
	        CertStore certStore = CertStore.getInstance("Collection", certStoreParams);
	        X509CertSelector certSelector = new X509CertSelector();
	        certSelector.setCertificate(certificate);
	        certSelector.setSubject(certificate.getSubjectX500Principal());

			PKIXBuilderParameters params = new PKIXBuilderParameters(getTrustAnchors(), certSelector);
			params.addCertStore(certStore);
            params.setSigProvider(DigipostSecurity.PROVIDER_NAME);
            params.setRevocationEnabled(false);
			CertPath certpath = CertPathBuilder.getInstance(PKIX).build(params).getCertPath();
			if (certpath.getCertificates().size() > 1) {
				return new ReviewedCertPath(certpath, this::trusts);
			} else {
				Logger thisShouldNeverHappen = LoggerFactory.getLogger(LOG.getName() + ".ThisShouldNeverHappen");
				thisShouldNeverHappen.warn("The resolved CertPath did not contain any trusted issuer, only the certificate [{}], supposedly issued by [{}]. " +
										   "This is not expected to happen, but we will try to find trust anchor certificate with some nasty use of BouncyCastle.", certificate.getSubjectDN(), certificate.getIssuerX500Principal());
				thisShouldNeverHappen.info("The hypthesis is that this else-code block can be removed (or replaced with logging an error and returning UNDECIDED). " +
										   "However, if this log message happens in production, and the sertificate validates OK, it must be kept in place. Talk to Rune if you need more information.");
				CertificateFactory cf = DigipostSecurity.getX509CertificateFactory();
				Optional<X509Certificate> issuer = CertHelper.findTrustAchorCert(certificate, getTrustAnchors());
				return new ReviewedCertPath(cf.generateCertPath(concat(Stream.of(certificate), issuer.map(Stream::of).orElse(Stream.empty())).collect(toList())), path -> issuer.isPresent());
			}

		} catch (GeneralSecurityException e) {
			LOG.warn("Error generating cert path. Certificate {} is not issued by trusted issuer. {}: {}", describe(certificate), e.getClass().getSimpleName(), e.getMessage());
			LOG.debug(exceptionNameAndMessage.apply(e), e);
			return new ReviewedCertPath(e);
		}
	}

	/**
	 * Determine if a certificate path is trusted or not
	 *
	 * @param certPath
	 * @return <code>true</code> if the path is trusted, <code>false</code> otherwise.
	 */
	public boolean trusts(final CertPath certPath) {
		try {
			Set<TrustAnchor> trustAnchors = getTrustAnchors();
			PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setSigProvider(DigipostSecurity.PROVIDER_NAME);
            params.setRevocationEnabled(false);
            CertPathValidator.getInstance(PKIX).validate(certPath, params);
            return true;
		} catch (CertPathValidatorException e) {
			return false;
		} catch (GeneralSecurityException e) {
			throw asUnchecked.apply(e);
		}
	}


	public Set<TrustAnchor> getTrustAnchors() {
		return getTrustAnchorCertificates().stream().map(c -> new TrustAnchor(c, null)).collect(toSet());
	}

	public Set<X509Certificate> getTrustAnchorCertificates() {
		return trustedCerts;
	}

	public KeyStore getTrustAnchorsKeyStore() {
		return asKeyStore(this.getTrustAnchorCertificates());
	}

	public Map<X500Principal, List<X509Certificate>> getTrustedIntermediateCertificates() {
		return trustedIntermediateCerts;
	}

	public Stream<X509Certificate> getAllTrustedCertificatesFor(X500Principal principal) {
		return concat(getTrustAnchorCertificates().stream(), getTrustedIntermediateCertificates().getOrDefault(principal, emptyList()).stream());
	}

}
