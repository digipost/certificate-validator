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
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.SocketTimeoutException;
import java.security.cert.X509Certificate;
import java.util.List;

import static uk.co.probablyfine.matchers.Java8Matchers.where;
import static uk.co.probablyfine.matchers.Java8Matchers.whereNot;
import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class OcspLookupTest {

    @Mock
    private CloseableHttpClient httpClient;

    @Mock
    private CloseableHttpResponse response;

    @Mock
    private StatusLine ocspResponseStatus;

    @Mock
    private HttpEntity ocspResponseEntity;

    private X509Certificate digipostCertificate;

    private X509Certificate verisignCertificate;


    @BeforeEach
    public void loadCertificates() {
        List<X509Certificate> certificates = DigipostSecurity.readCertificates("digipost.no-certchain.pem").collect(toList());
        assertThat(certificates, hasSize(3));
        digipostCertificate = certificates.get(0);
        verisignCertificate = certificates.get(1);
    }


    @Test
    public void exceptionFromHttpRequestAreRethrown() throws Exception {
        given(httpClient.execute(any())).will(i -> { throw new SocketTimeoutException("timed out"); });

        OcspLookup lookup = OcspLookupRequest.tryCreate(digipostCertificate, verisignCertificate).map(OcspLookup::new).get();
        Exception thrown = assertThrows(Exception.class, () -> lookup.executeUsing(httpClient));
        assertThat(thrown, where(Exception::getMessage, containsString(SocketTimeoutException.class.getSimpleName())));
        assertThat(thrown, where(Exception::getMessage, containsString("timed out")));
    }

    @Test
    public void non200ResponseIsNotOk() throws Exception {
        when(httpClient.execute(any())).thenReturn(response);
        when(response.getStatusLine()).thenReturn(ocspResponseStatus);

        given(ocspResponseStatus.getStatusCode()).willReturn(500);

        OcspLookup lookup = OcspLookupRequest.tryCreate(digipostCertificate, verisignCertificate).map(OcspLookup::new).get();
        OcspResult result = lookup.executeUsing(httpClient);
        assertThat(result, whereNot(OcspResult::isOkResponse));
    }

    @Test
    public void a200ResponseIsOk() throws Exception {
        when(httpClient.execute(any())).thenReturn(response);
        when(response.getStatusLine()).thenReturn(ocspResponseStatus);

        given(ocspResponseStatus.getStatusCode()).willReturn(200);

        OcspLookup lookup = OcspLookupRequest.tryCreate(digipostCertificate, verisignCertificate).map(OcspLookup::new).get();
        try (OcspResult result = lookup.executeUsing(httpClient)) {
            assertThat(result, where(OcspResult::isOkResponse));
        }
    }

}
