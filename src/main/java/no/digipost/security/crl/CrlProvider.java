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
package no.digipost.security.crl;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * Provides CRLs supplied by the application, e.g. loaded from file. A provided CRL is
 * preferred over downloading from the CRL distribution points of a certificate.
 * The provided CRL is still verified to be issued and signed by the issuer, and to be
 * current, before it is used.
 */
@FunctionalInterface
public interface CrlProvider {

    /**
     * A provider which never provides any CRL.
     */
    CrlProvider NONE = issuer -> Optional.empty();


    /**
     * Create a provider for a fixed set of CRLs. If several CRLs are from the same issuer,
     * the most recent one is provided.
     *
     * @param crls the CRLs
     * @return the provider
     */
    static CrlProvider of(Collection<X509CRL> crls) {
        List<X509CRL> copy = new ArrayList<>(crls);
        return issuer -> copy.stream()
                .filter(crl -> crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()))
                .max(Comparator.comparing(X509CRL::getThisUpdate));
    }


    /**
     * Get a CRL issued by the given certificate.
     *
     * @param issuer the certificate which has issued the CRL
     * @return the CRL, or {@link Optional#empty()} if no CRL is available for the issuer.
     */
    Optional<X509CRL> crlIssuedBy(X509Certificate issuer);

}
