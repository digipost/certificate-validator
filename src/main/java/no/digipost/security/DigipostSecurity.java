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
package no.digipost.security;

import no.digipost.security.cert.CertificateNotFound;
import no.digipost.security.cert.internal.JavaSecurityUtils;
import no.digipost.security.keystore.KeyStoreBuilder;
import no.digipost.security.keystore.KeyStoreType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toList;
import static java.util.stream.StreamSupport.stream;


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
    public static final String X509 = JavaSecurityUtils.X509;


    private static final Logger LOG = LoggerFactory.getLogger(DigipostSecurity.class);


    /**
     * Retrieve a {@link CertificateFactory} for X.509 certificates.
     */
    public static CertificateFactory getX509CertificateFactory() {
        return JavaSecurityUtils.getX509CertificateFactory();
    }

    /**
     * Read the first (or only) certificate from a resource.
     *
     * @param resourceName the name of the classpath resource containing the certificate.
     *
     * @see CertificateFactory#generateCertificate(InputStream)
     */
    public static X509Certificate readCertificate(String resourceName) {
        return readCertificates(resourceName).findFirst().orElseThrow(() -> new CertificateNotFound(resourceName));
    }


    /**
     * Read the first (or only) certificate from an array of bytes.
     *
     * @param certificateBytes the bytes containing the certificate.
     */
    public static X509Certificate readCertificate(byte[] certificateBytes) {
        return readCertificate(new ByteArrayInputStream(certificateBytes));
    }


    /**
     * Read the first (or only) certificate from a resource.
     *
     * @see CertificateFactory#generateCertificate(InputStream)
     */
    public static X509Certificate readCertificate(InputStream certificateResource) {
        return readCertificates(certificateResource).findFirst().orElseThrow(() -> new CertificateNotFound());
    }


    /**
     * Read several certificates from a single resource.
     *
     * @param resourceName the name of the classpath resource containing the certificates.
     *
     * @see CertificateFactory#generateCertificates(InputStream)
     */
    public static Stream<X509Certificate> readCertificates(String resourceName) {
        try (InputStream certificateResource = requireNonNull(DigipostSecurity.class.getClassLoader().getResourceAsStream(resourceName), resourceName + " not found on classpath!")) {
            return readCertificates(certificateResource);
        } catch (IOException e) {
            throw new RuntimeException("Error reading certificate from " + resourceName + ": " + e.getMessage(), e);
        }
    }


    /**
     * Read several certificates from a byte array.
     *
     * @param certificatesBytes the bytes containing the certificates.
     *
     * @see CertificateFactory#generateCertificates(InputStream)
     */
    public static Stream<X509Certificate> readCertificates(byte[] certificatesBytes) {
        return readCertificates(new ByteArrayInputStream(certificatesBytes));
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
     * Convert a {@link CertPath} to a stream of certificates. The certificates
     * are casted to {@link X509Certificate}.
     *
     * @param path the CertPath
     * @return stream of {@value #X509} certificates, aqcuired from {@link CertPath#getCertificates()}.
     */
    public static Stream<X509Certificate> asStream(CertPath path) {
        return path.getCertificates().stream().map(DigipostSecurity::requireX509);
    }


    /**
     * Put certificates into a new {@link KeyStore} of type {@link KeyStoreType#JCEKS}. They
     * will be aliased as their Subject DNs.
     *
     * @deprecated Use
     *   {@link KeyStoreType#JCEKS JCEKS}.{@link KeyStoreType#newKeyStore() newKeyStore()}
     *   instead, and add certificates using e.g. {@link KeyStoreBuilder#containing(java.util.Collection)}.
     */
    @Deprecated
    public static KeyStore asKeyStore(Iterable<X509Certificate> certificates) {
        return KeyStoreType.JCEKS
                .newKeyStore()
                .containing(stream(certificates.spliterator(), false), cert -> cert.getSubjectDN().toString())
                .withNoPassword();
    }


    /**
     * Build a {@link CertPath} from the given certificates.
     *
     * @param certificates the {@value #X509} certificates.
     * @return the certification path
     */
    public static CertPath asCertPath(Stream<X509Certificate> certificates) {
        List<X509Certificate> collectedCertificates = certificates.collect(toList());
        try {
            return getX509CertificateFactory().generateCertPath(collectedCertificates);
        } catch (CertificateException e) {
            throw new DigipostSecurityException(e);
        }
    }


    /**
     * Create a description of a certificate, applicable for logging and similar.
     * The description will be multiline, where the certificate is on the first line,
     * and each issuer will be on its own line below.
     *
     * @param certPath the certificate path to describe
     * @return the multiline description.
     */
    public static String describe(CertPath certPath) {
        return JavaSecurityUtils.describe(certPath);
    }

    /**
     * Create a description of a certificate, applicable for logging and similar.
     *
     * @param certificate the certificate to describe
     * @return the description
     */
    public static String describe(Certificate certificate) {
        return JavaSecurityUtils.describe(certificate);
    }



    private static volatile boolean securityProviderSet = false;
    private static volatile boolean cryptoPolicyPropertySet = false;

    /**
     * This is called by the static initializer of the {@link DigipostSecurity} class,
     * and should not be necessary to explicitly invoke.
     */
    public static void ensureSecurityProvider() {
        ensureCryptoPolicyUnlimited();
        if (!securityProviderSet) {
            synchronized (Security.class) {
                if (Security.getProvider(PROVIDER_NAME) == null) {
                    Security.addProvider(new BouncyCastleProvider());
                    securityProviderSet = true;
                    LOG.info("Security provider " + PROVIDER_NAME + " added: " + BouncyCastleProvider.class.getName());
                }
            }
        }
    }



    /**
     * Sets the security property {@code crypto.policy} to "unlimited" to enable Java Cryptography Extension (JCE) Unlimited Strength.
     * This is also invoked by {@link #ensureSecurityProvider()}.
     * <p>
     * Note: <em>setting this security property this only has effect on Java 8 b152 or newer</em>. On earlier Java versions one must still
     * separately download and add the JCE Unlimited Strength Jurisdiction Policy Files.
     *
     * @see <a href="http://www.oracle.com/technetwork/java/javase/8u152-relnotes-3850503.html#JDK-8157561">www.oracle.com/technetwork/java/javase/8u152-relnotes-3850503.html#JDK-8157561</a>
     */
    public static void ensureCryptoPolicyUnlimited() {
        if (!cryptoPolicyPropertySet) {
            Security.setProperty("crypto.policy", "unlimited"); // only effective on Java 8 b152 or newer
            cryptoPolicyPropertySet = true;
            LOG.info("Security policy set: crypto.policy=unlimited");
        }
    }


    /**
     * This method may be invoked to verify that Java Cryptography Extension (JCE) Unlimited Strength is
     * enabled.
     *
     * @throws DigipostSecurityException if Java Cryptography Extension (JCE) Unlimited Strength can not be
     *                                   verified to be enabled.
     */
    public static void verifyJceUnlimitedStrength() {
        try {
            int aesMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            if(aesMaxKeyLength != Integer.MAX_VALUE) {
                throw new DigipostSecurityException("Java Cryptography Extension (JCE) Unlimited Strength not enabled! Maximum allowed key length for AES is " + aesMaxKeyLength);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new DigipostSecurityException("Error when verifying the maximum key length for the AES algorithm. Is Java Cryptography Extension (JCE) Unlimited Strength enabled?", e);
        }
    }

    static {
        ensureSecurityProvider();
    }

    private DigipostSecurity() {}

}
