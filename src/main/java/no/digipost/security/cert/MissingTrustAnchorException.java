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
package no.digipost.security.cert;

import no.digipost.security.DigipostSecurity;
import no.digipost.security.DigipostSecurityException;

import java.security.cert.X509Certificate;
import java.util.List;

import static java.util.stream.Collectors.joining;

public class MissingTrustAnchorException extends DigipostSecurityException {

    private final List<X509Certificate> certificates;

    public MissingTrustAnchorException(List<X509Certificate> certificates) {
        super(
                certificates.size() + " certificates missing trust anchor certificates: " +
                certificates.stream().map(DigipostSecurity::describe).collect(joining(", ")));
        this.certificates = certificates;
    }

    /**
     * @return the certificates where trust anchors could not be located
     */
    public List<X509Certificate> getCertificates() {
        return certificates;
    }

}
