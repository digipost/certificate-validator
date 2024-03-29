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
package no.digipost.security;

import jakarta.servlet.ServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class HttpsTest {

    private static final X509Certificate x509Cert = DigipostSecurity.readCertificate("verisign.pem");

    @Mock
    private ServletRequest request;


    @Test
    void doesNotAllowNonSecureRequest() {
        assertThrows(NotSecure.class, () -> Https.extractClientCertificate(request));
    }

    @Test
    void extractsSingleX509Certificate() {
        given(request.isSecure()).willReturn(true);
        given(request.getAttribute(Https.REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE)).willReturn(x509Cert);

        assertThat(Https.extractClientCertificate(request), is(x509Cert));
    }

    @Test
    void extractFirstOfMultipleX509Certificates() {
        given(request.isSecure()).willReturn(true);
        given(request.getAttribute(Https.REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE)).willReturn(new Object[]{x509Cert, "garbage"});

        assertThat(Https.extractClientCertificate(request), is(x509Cert));
    }

    @Test
    void failsIfNotX509Certificate() {
        given(request.isSecure()).willReturn(true);
        given(request.getAttribute(Https.REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE)).willReturn(new Object[]{mock(Certificate.class)});

        assertThrows(IllegalCertificateType.class, () -> Https.extractClientCertificate(request));
    }

    @Test
    void failsOnEmptyArray() {
        given(request.isSecure()).willReturn(true);
        given(request.getAttribute(Https.REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE)).willReturn(new Object[0]);

        assertThrows(IllegalCertificateType.class, () -> Https.extractClientCertificate(request));
    }



}
