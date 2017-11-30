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
package no.digipost.security.ocsp;

import no.digipost.security.DigipostSecurity;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.net.SocketTimeoutException;
import java.security.cert.X509Certificate;
import java.util.List;

import static java.util.stream.Collectors.toList;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.when;

public class OcspLookupTest {

    @Rule
    public final MockitoRule mockito = MockitoJUnit.rule();

    @Rule
    public final ExpectedException expectedException = ExpectedException.none();

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


    @Before
    public void loadCertificates() {
        List<X509Certificate> certificates = DigipostSecurity.readCertificates("digipost.no-certchain.pem").collect(toList());
        assertThat(certificates, hasSize(3));
        digipostCertificate = certificates.get(0);
        verisignCertificate = certificates.get(1);
    }



    @Test
    public void extractsTheOcspResponderUriFromCertificate() throws Exception {
        OcspLookup lookup = OcspLookup.newLookup(digipostCertificate, verisignCertificate).get();
        assertThat(lookup.uri, is("http://sr.symcd.com"));
    }

    @Test
    public void certificateIdSerialnumberFromCertificate() {
        OcspLookup lookup = OcspLookup.newLookup(digipostCertificate, verisignCertificate).get();
        assertThat(lookup.certificateId.getSerialNumber(), is(digipostCertificate.getSerialNumber()));
    }

    @Test
    public void exceptionFromHttpRequestAreRethrown() throws Exception {
        given(httpClient.execute(any())).will(i -> { throw new SocketTimeoutException("timed out"); });

        OcspLookup lookup = OcspLookup.newLookup(digipostCertificate, verisignCertificate).get();
        expectedException.expectMessage(SocketTimeoutException.class.getSimpleName());
        expectedException.expectMessage("timed out");
        lookup.executeUsing(httpClient);
    }

    @Test
    public void non200ResponseIsNotOk() throws Exception {
        when(httpClient.execute(any())).thenReturn(response);
        when(response.getStatusLine()).thenReturn(ocspResponseStatus);

        given(ocspResponseStatus.getStatusCode()).willReturn(500);

        OcspLookup lookup = OcspLookup.newLookup(digipostCertificate, verisignCertificate).get();
        OcspResult result = lookup.executeUsing(httpClient);
        assertFalse(result.isOkResponse());
    }

    @Test
    public void a200ResponseIsOk() throws Exception {
        when(httpClient.execute(any())).thenReturn(response);
        when(response.getStatusLine()).thenReturn(ocspResponseStatus);

        given(ocspResponseStatus.getStatusCode()).willReturn(200);

        OcspLookup lookup = OcspLookup.newLookup(digipostCertificate, verisignCertificate).get();
        try (OcspResult result = lookup.executeUsing(httpClient)) {
            assertTrue(result.isOkResponse());
        }
    }

}
