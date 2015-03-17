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
package no.digipost.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.InputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import static java.util.stream.Collectors.joining;

public final class DigipostSecurity {


	/**
	 * Name of the security provider: {@value #PROVIDER_NAME}
	 */
	public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

	/**
	 * String denoting Public-Key Infrastructure ({@value #PKIX}).
	 */
	public static final String PKIX = "PKIX";

	/**
	 * String denoting the certificate type {@value #X509}.
	 */
	public static final String X509 = "X.509";



	/**
	 * Retrieve a {@link CertificateFactory} for X.509 certificates.
	 */
	public static CertificateFactory getX509CertificateFactory() {
		 try {
	        return CertificateFactory.getInstance(X509);
        } catch (CertificateException e) {
	        throw new RuntimeException(
	        		"Could not create " + X509 + " certificate factory: '" + e.getMessage() + "'. " +
	        		"Available providers: " + Stream.of(Security.getProviders()).map(Provider::getName).collect(joining(", ")), e);
        }
	}

	/**
	 * Read the first (or only) certificate from a resource.
	 *
	 * @param resourceName the name of the classpath resource containing the certificates.
	 *
	 * @see CertificateFactory#generateCertificate(InputStream)
	 */
	public static X509Certificate readCertificate(String resourceName) {
		return readCertificates(resourceName).findFirst().orElseThrow(() -> new RuntimeException("No certificates found in " + resourceName));
	}

	/**
	 * Read the first (or only) certificate from a resource.
	 *
	 * @see CertificateFactory#generateCertificate(InputStream)
	 */
	public static X509Certificate readCertificate(InputStream certificateResource) {
		return readCertificates(certificateResource).findFirst().get();
	}

	/**
	 * Read several certificates from a single resource.
	 *
	 * @param resourceName the name of the classpath resource containing the certificates.
	 *
	 * @see CertificateFactory#generateCertificates(InputStream)
	 */
	public static Stream<X509Certificate> readCertificates(String resourceName) {
		InputStream certificateResource = DigipostSecurity.class.getClassLoader().getResourceAsStream(resourceName);
		if (certificateResource == null) {
			throw new RuntimeException(resourceName + " not found");
		}
		return readCertificates(certificateResource);
	}

	/**
	 * Read several certificates from a single resource.
	 *
	 * @see CertificateFactory#generateCertificates(InputStream)
	 */
	public static Stream<X509Certificate> readCertificates(InputStream certificatesResource) {
		try {
	        return getX509CertificateFactory().generateCertificates(certificatesResource).stream().map(DigipostSecurity::requireX509);
        } catch (CertificateException e) {
	        throw new RuntimeException("Unable to generate certificate: " + e.getMessage(), e);
        }
	}

	/**
	 * Cast Certificate to {@link X509Certificate}, or throw appropriate exception.
	 *
	 * @throws IllegalCertificateType if the given certificate is not of type {@value #X509}.
	 */
	public static X509Certificate requireX509(Certificate certificate) {
		if (certificate instanceof X509Certificate) {
        	return (X509Certificate) certificate;
        } else {
        	throw new IllegalCertificateType(certificate);
        }
	}


	/**
	 * This is called by the static initializer of the {@link DigipostSecurity} class,
	 * and is not necessary to explicitly invoke.
	 */
	public static void ensureSecurityProvider() {
		synchronized (Security.class) {
			if (Security.getProvider(PROVIDER_NAME) == null) {
				Security.addProvider(new BouncyCastleProvider());
			}
		}
	}

	static {
		ensureSecurityProvider();
	}

	private DigipostSecurity() {}
}
