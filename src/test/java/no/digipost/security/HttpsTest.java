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
package no.digipost.security;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import javax.servlet.ServletRequest;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

public class HttpsTest {

    private static final X509Certificate x509Cert = DigipostSecurity.readCertificate("verisign.pem");

    @Rule
    public final MockitoRule mockito = MockitoJUnit.rule();

    @Rule
    public final ExpectedException expectedException = ExpectedException.none();

    @Mock
    private ServletRequest request;


    @Test
    public void doesNotAllowNonSecureRequest() {
        expectedException.expect(NotSecure.class);
        Https.extractClientCertificate(request);
    }

    @Test
    public void extractsSingleX509Certificate() {
        given(request.isSecure()).willReturn(true);
        given(request.getAttribute(Https.REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE)).willReturn(x509Cert);

        assertThat(Https.extractClientCertificate(request), is(x509Cert));
    }

    @Test
    public void extractFirstOfMultipleX509Certificates() {
        given(request.isSecure()).willReturn(true);
        given(request.getAttribute(Https.REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE)).willReturn(new Object[]{x509Cert, "garbage"});

        assertThat(Https.extractClientCertificate(request), is(x509Cert));
    }

    @Test
    public void failsIfNotX509Certificate() {
        given(request.isSecure()).willReturn(true);
        given(request.getAttribute(Https.REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE)).willReturn(new Object[]{mock(Certificate.class)});

        expectedException.expect(IllegalCertificateType.class);
        Https.extractClientCertificate(request);
    }

    @Test
    public void failsOnEmptyArray() {
        given(request.isSecure()).willReturn(true);
        given(request.getAttribute(Https.REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE)).willReturn(new Object[0]);

        expectedException.expect(IllegalCertificateType.class);
        Https.extractClientCertificate(request);
    }



}
