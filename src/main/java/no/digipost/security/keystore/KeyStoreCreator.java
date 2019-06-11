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
import java.util.function.Function;

public interface KeyStoreCreator {

    /**
     * Create a new {@link KeyStore key store} of the type decided by this instance of {@link KeyStoreCreator}.
     * The key store will be initialized as empty.
     *
     * @return the new key store.
     */
    KeyStore newKeyStore();

    /**
     * Create a {@link #newKeyStore() new key store} containing the given certificates, which will be aliased using
     * their Subject DNs, {@link X509Certificate#getSerialNumber() serial numbers}, and Issuer DNs to ensure unique
     * aliases.
     * <p>
     * If you wish to retrieve the certificates using aliases, consider {@link #newKeyStoreContaining(Iterable, Function)}
     * instead.
     *
     * @param certificates the certificates to add to the new {@link KeyStore}.
     *
     * @return the new key store
     */
    default KeyStore newKeyStoreContaining(Iterable<X509Certificate> certificates) {
        return newKeyStoreContaining(certificates, cert -> cert.getSubjectX500Principal().getName() + "-" + cert.getSerialNumber() + "-" + cert.getIssuerX500Principal().getName());
    }

    /**
     * Create a {@link #newKeyStore() new key store} containing the given certificates, which will be aliased using
     * their Subject DNs, {@link X509Certificate#getSerialNumber() serial numbers}, and Issuer DNs to ensure unique
     * aliases.
     * <p>
     * If you wish to retrieve the certificates using aliases, consider {@link #newKeyStoreContaining(Iterable, Function)}
     * instead.
     *
     * @param certificates the certificates to add to the new {@link KeyStore}.
     * @param aliasCreater creates an alias for each certificate in the new key store.
     *
     * @return the new key store
     *
     * @throws DuplicateAlias if the same alias is created for several certificates.
     */
    default KeyStore newKeyStoreContaining(Iterable<X509Certificate> certificates, Function<? super X509Certificate, String> aliasCreater) {
        KeyStore keystore = newKeyStore();
        try {
            for (X509Certificate cert : certificates) {
                String alias = aliasCreater.apply(cert);
                if (keystore.isCertificateEntry(alias)) {
                    throw new DuplicateAlias(alias, keystore.getCertificate(alias), cert);
                }
                keystore.setCertificateEntry(alias, cert);
            }
            return keystore;
        } catch (KeyStoreException e) {
            throw new DigipostSecurityException(e);
        }
    }

    /**
     * Load key store from {@code InputStream} into a new {@link KeyStore}.
     *
     * @param keyStoreStream the {@code InputStream} containing the key store
     * @param keyStorePassword the password for the key store
     *
     * @return the new {@code KeyStore}
     */
    default KeyStore newKeyStoreLoadedFrom(InputStream keyStoreStream, String keyStorePassword) {
        if (keyStoreStream == null) {
            throw new IllegalArgumentException("Failed to initialize key store, because the key store stream is null. Please specify a stream with data.");
        }

        KeyStore ks = newKeyStore();
        try {
            ks.load(keyStoreStream, keyStorePassword.toCharArray());
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new DigipostSecurityException(
                    "Unable to load key store instance of type " + this +
                    ", because " + e.getClass().getSimpleName() + ": '" + e.getMessage() + "'", e);
        }
        return ks;
    }

}
