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

public class Trust {

	private static final Logger LOG = LoggerFactory.getLogger(Trust.class);

	private final Set<X509Certificate> trustedCerts;
	private final Map<X500Principal, List<X509Certificate>> trustedIntermediateCerts;

	public Trust(Stream<X509Certificate> rootCertificates, Stream<X509Certificate> intermediateCertificates) {
		this.trustedCerts = unmodifiableSet(rootCertificates.collect(toSet()));
		this.trustedIntermediateCerts = unmodifiableMap(intermediateCertificates.collect(groupingBy(X509Certificate::getSubjectX500Principal)));
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

	public ReviewedCertPath resolveCertPath(X509Certificate sertifikat) {
		try {
			CollectionCertStoreParameters certStoreParams = new CollectionCertStoreParameters(getAllTrustedCertificatesFor(sertifikat.getIssuerX500Principal()).collect(toSet()));
	        CertStore certStore = CertStore.getInstance("Collection", certStoreParams);
	        X509CertSelector certSelector = new X509CertSelector();
	        certSelector.setCertificate(sertifikat);
	        certSelector.setSubject(sertifikat.getSubjectX500Principal());

			PKIXBuilderParameters params = new PKIXBuilderParameters(getTrustAnchors(), certSelector);
			params.addCertStore(certStore);
            params.setSigProvider(DigipostSecurity.PROVIDER_NAME);
            params.setRevocationEnabled(false);
			CertPath certpath = CertPathBuilder.getInstance(PKIX).build(params).getCertPath();
			if (certpath.getCertificates().size() > 1) {
				return new ReviewedCertPath(certpath, this::trusts);
			} else {
				CertificateFactory cf = CertificateFactory.getInstance(X509, DigipostSecurity.PROVIDER_NAME);
				Optional<X509Certificate> issuer = CertHelper.findTrustAchorCert(sertifikat, getTrustAnchors());
				return new ReviewedCertPath(cf.generateCertPath(concat(Stream.of(sertifikat), issuer.map(Stream::of).orElse(Stream.empty())).collect(toList())), path -> issuer.isPresent());
			}

		} catch (GeneralSecurityException e) {
			LOG.warn("Error generating cert path. Certificate is not issued by trusted issuer. " + e.getClass().getSimpleName() + ": " + e.getMessage());
			LOG.debug(exceptionNameAndMessage.apply(e), e);
			return new ReviewedCertPath(e);
		}
	}

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

}
