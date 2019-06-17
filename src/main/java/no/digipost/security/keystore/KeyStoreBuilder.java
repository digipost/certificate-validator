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
package no.digipost.security.keystore;

import no.digipost.security.DigipostSecurityException;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

public final class KeyStoreBuilder {

    /**
     * The default way to create aliases for certificates, which uses certificates'
     * Subject DNs, {@link X509Certificate#getSerialNumber() serial numbers}, and Issuer DNs
     * to create aliases. This alias creator is to ensure unique aliases for added certificates,
     * and should not be used for adding certificates which one wishes to retrieve by alias from
     * the resulting key store.
     */
    public static final Function<? super X509Certificate, String> DEFAULT_ALIAS_CREATOR =
            cert -> cert.getSubjectX500Principal().getName() + "-" + cert.getSerialNumber() + "-" + cert.getIssuerX500Principal().getName();

    private final KeyStoreType type;
    private final Map<String, X509Certificate> certificates;
    private String keyStoreClasspathResourceName;
    private InputStream keyStoreStream;

    public KeyStoreBuilder(KeyStoreType type) {
        this.type = type;
        this.certificates = new LinkedHashMap<>();
    }


    /**
     * Add a certificate which should be contained in the resulting {@link KeyStore}. Its
     * alias will be created by {@link #DEFAULT_ALIAS_CREATOR}.
     *
     * @param certificate the certificate to add to the resulting key store.
     *
     * @return the builder
     */
    public KeyStoreBuilder containing(X509Certificate certificate) {
        return containing(Stream.of(certificate));
    }


    /**
     * Add a certificate which should be contained in the resulting {@link KeyStore} with the given alias.
     *
     * @param certificate the certificate to add to the resulting key store.
     * @param alias the alias which the certificate may be retrieved from the resulting key store.
     *
     * @return the builder
     */
    public KeyStoreBuilder containing(X509Certificate certificate, String alias) {
        return containing(Stream.of(certificate), c -> alias);
    }


    /**
     * Add certificates which should be contained in the resulting key store, and which will be aliased using
     * {@link #DEFAULT_ALIAS_CREATOR}.
     *
     * @param certificates the certificates to add to the new {@link KeyStore}.
     *
     * @return the builder.
     */
    public KeyStoreBuilder containing(Collection<X509Certificate> certificates) {
        return containing(certificates.stream());
    }


    /**
     * Add certificates which should be contained in the resulting key store, and which will be aliased using
     * {@link #DEFAULT_ALIAS_CREATOR}.
     *
     * @param certificates the certificates to add to the new {@link KeyStore}.
     *
     * @return the builder.
     */
    public KeyStoreBuilder containing(Stream<X509Certificate> certificates) {
        return containing(certificates, DEFAULT_ALIAS_CREATOR);
    }


    /**
     * Add certificates which should be contained in the resulting key store.
     *
     * @param certificates the certificates to add to the new {@link KeyStore}.
     * @param aliasCreator creates an alias for each certificate in the new key store.
     *
     * @return the builder.
     *
     * @throws DuplicateAlias if the same alias is created for several certificates.
     */
    public KeyStoreBuilder containing(Stream<X509Certificate> certificates, Function<? super X509Certificate, String> aliasCreator) {
        certificates.forEach(cert -> {
            String alias = aliasCreator.apply(cert);
            this.certificates.merge(alias, cert, (existing, collision) -> { throw new DuplicateAlias(alias, existing, collision); });
        });
        return this;
    }


    /**
     * Load key store from classpath resource into a new {@link KeyStore}.
     *
     * @param classpathResourceName the name of the classpath resource containing the key store. The resource is
     *                              resolved from the root of the classpath.
     */
    public KeyStoreBuilder loadFromClasspath(String classpathResourceName) {
        if (classpathResourceName == null) {
            throw new IllegalArgumentException("Classpath resource name is null");
        }
        this.keyStoreClasspathResourceName = classpathResourceName.replaceFirst("^/(?=.+)", "");
        this.keyStoreStream = null;
        return this;
    }


    /**
     * Load key store from {@code InputStream} into a new {@link KeyStore}.
     *
     * @param keyStoreStream the {@code InputStream} containing the key store.
     */
    public KeyStoreBuilder loadFrom(InputStream keyStoreStream) {
       if (keyStoreStream == null) {
           throw new IllegalArgumentException("Key store InputStream is null. Please specify a stream with data.");
       }
       this.keyStoreStream = keyStoreStream;
       this.keyStoreClasspathResourceName = null;
       return this;
    }


    /**
     * Build a new key store with no password to access its content.
     *
     * @return the new {@link KeyStore}.
     */
    public KeyStore withNoPassword() {
        return withPassword((char[]) null);
    }


    /**
     * Build a new key store with the given password to access its content.
     *
     * @param password the password for the key store.
     *
     * @return the new {@link KeyStore}.
     */
    public KeyStore withPassword(String password) {
        return withPassword(password == null ? null : password.toCharArray());
    }


    /**
     * Build a new key store with the given password to access its content.
     *
     * @param password the password for the key store.
     *
     * @return the new {@link KeyStore}.
     */
    public KeyStore withPassword(char[] password) {
        KeyStore initializedKeyStore = initNewKeyStore((newKeyStore, content) -> newKeyStore.load(content.orElse(null), password));
        if (!certificates.isEmpty()) {
            try {
                for (Map.Entry<String, X509Certificate> certificate : this.certificates.entrySet()) {
                    String alias = certificate.getKey();
                    if (initializedKeyStore.isCertificateEntry(alias)) {
                        throw new DuplicateAlias(alias, initializedKeyStore.getCertificate(alias), certificate.getValue());
                    }
                    initializedKeyStore.setCertificateEntry(alias, certificate.getValue());
                }
            } catch (KeyStoreException e) {
                throw new DigipostSecurityException(e);
            }
        }
        return initializedKeyStore;
    }


    private KeyStore initNewKeyStore(KeyStoreInitializer initializeKeyStore) {
        try {
            KeyStore newKeyStore = KeyStore.getInstance(type.typeName);
            if (keyStoreClasspathResourceName != null) {
                try (InputStream keyStoreStream = KeyStoreBuilder.class.getClassLoader().getResourceAsStream(keyStoreClasspathResourceName)) {
                    if (keyStoreStream == null) {
                        throw new IllegalArgumentException("Unable to locate " + keyStoreClasspathResourceName + " on classpath");
                    }
                    initializeKeyStore.apply(newKeyStore, Optional.of(keyStoreStream));
                }
            } else {
                initializeKeyStore.apply(newKeyStore, Optional.ofNullable(keyStoreStream));
            }
            return newKeyStore;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new DigipostSecurityException(
                    "Unable to load key store instance of type " + this +
                    ", because " + e.getClass().getSimpleName() + ": '" + e.getMessage() + "'", e);
        }
    }

    private interface KeyStoreInitializer {
        void apply(KeyStore keyStore, Optional<InputStream> keyStoreStream) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException;
    }

}
