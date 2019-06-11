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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public enum KeyStoreType implements KeyStoreCreator {

    /**
     * Java Cryptography Extension Key Store type
     */
    JCEKS("JCEKS"),

    /**
     * PKCS #12 Key Store type
     */
    PKCS12("PKCS12");


    private String typeName;

    KeyStoreType(String typeName) {
        this.typeName = typeName;
    }

    @Override
    public KeyStore newKeyStore() {
        try {
            KeyStore newKeyStore = KeyStore.getInstance(typeName);
            newKeyStore.load(null, null);
            return newKeyStore;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new DigipostSecurityException(e);
        }
    }
}
