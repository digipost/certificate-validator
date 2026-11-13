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
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;

/**
 * Provides CRLs from the application, e.g. loaded from file. These are preferred over
 * downloading, but are still verified before use. The most recent usable CRL is used.
 */
@FunctionalInterface
public interface CrlProvider {

    /**
     * A provider which never provides any CRL.
     */
    CrlProvider NONE = issuer -> emptyList();


    /**
     * Create a provider for a fixed set of CRLs. For each issuer, all CRLs with the issuer's name
     * are provided.
     *
     * @param crls the CRLs
     * @return the provider
     */
    static CrlProvider of(Collection<X509CRL> crls) {
        List<X509CRL> copy = new ArrayList<>(crls);
        return issuer -> copy.stream()
                .filter(crl -> crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()))
                .collect(toList());
    }


    /**
     * @param issuer the certificate which has issued the CRLs
     * @return the candidate CRLs, in any order, or empty if none is available for the issuer.
     *         They may include CRLs which are not usable, e.g. not yet valid or signed with another key.
     */
    List<X509CRL> crlsIssuedBy(X509Certificate issuer);

}
