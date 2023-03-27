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
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.SocketTimeoutException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.co.probablyfine.matchers.Java8Matchers.where;
import static uk.co.probablyfine.matchers.Java8Matchers.whereNot;

@ExtendWith(MockitoExtension.class)
class OcspLookupTest {

    private static X509Certificate digipostCertificate;

    private static X509Certificate verisignCertificate;

    private final OcspHttpClientMockitoHelper ocsp;

    public OcspLookupTest(@Mock CloseableHttpClient httpClient) {
        this.ocsp = new OcspHttpClientMockitoHelper(httpClient);
    }

    @BeforeAll
    static void loadCertificates() {
        List<X509Certificate> certificates = DigipostSecurity.readCertificates("digipost.no-certchain.pem").collect(toList());
        assertThat(certificates, hasSize(3));
        digipostCertificate = certificates.get(0);
        verisignCertificate = certificates.get(1);
    }


    @Test
    void exceptionFromHttpRequestAreRethrown() throws Exception {
        ocsp.whenExecutingOcspLookupRequest().thenThrow(new SocketTimeoutException("timed out"));

        OcspLookup lookup = OcspLookupRequest.tryCreate(digipostCertificate, verisignCertificate).map(OcspLookup::new).get();
        Exception thrown = assertThrows(Exception.class, () -> lookup.executeUsing(ocsp.httpClient));
        assertThat(thrown, where(Exception::getMessage, containsString(SocketTimeoutException.class.getSimpleName())));
        assertThat(thrown, where(Exception::getMessage, containsString("timed out")));
    }

    @Test
    void non200ResponseIsNotOk() throws Exception {
        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("https://ocsp.ca.com"), 500, null));

        OcspLookup lookup = OcspLookupRequest.tryCreate(digipostCertificate, verisignCertificate).map(OcspLookup::new).get();
        OcspResult result = lookup.executeUsing(ocsp.httpClient);
        assertThat(result, whereNot(OcspResult::isOkResponse));
    }

    @Test
    void a200ResponseIsOk() throws Exception {
        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("https://ocsp.ca.com"), 200, null));

        OcspLookup lookup = OcspLookupRequest.tryCreate(digipostCertificate, verisignCertificate).map(OcspLookup::new).get();
        OcspResult result = lookup.executeUsing(ocsp.httpClient);
        assertThat(result, where(OcspResult::isOkResponse));
    }

}
