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
package no.digipost.security.ocsp;

import no.digipost.security.DigipostSecurity;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static uk.co.probablyfine.matchers.Java8Matchers.where;

class OcspLookupRequestTest {

    private static final X509Certificate digipostCertificate;
    private static final X509Certificate verisignCertificate;

    static {
        List<X509Certificate> certificates = DigipostSecurity.readCertificates("digipost.no-certchain.pem").collect(toList());
        digipostCertificate = certificates.get(0);
        verisignCertificate = certificates.get(1);
    }

    private final OcspLookupRequest ocspLookupRequest = OcspLookupRequest.tryCreate(digipostCertificate, verisignCertificate).get();


    @Test
    void extractsTheOcspResponderUriFromCertificate() {
        assertThat(ocspLookupRequest, where(request -> request.url, is(URI.create("http://sr.symcd.com"))));
    }

    @Test
    void certificateIdSerialnumberFromCertificate() {
        assertThat(ocspLookupRequest.certificateSerialNumber, is(digipostCertificate.getSerialNumber()));
    }

}
