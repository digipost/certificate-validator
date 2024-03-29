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

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static java.util.Optional.empty;
import static no.digipost.security.ocsp.OcspUtils.findOscpSigningCertificate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

class OcspUtilsTest {

    @Test
    void ocspResponseWithNoSigningCertificates() {
        BasicOCSPResp ocspResponse = mock(BasicOCSPResp.class);
        given(ocspResponse.getCerts()).willReturn(null);
        assertThat(findOscpSigningCertificate(ocspResponse), is(empty()));

        given(ocspResponse.getCerts()).willReturn(new X509CertificateHolder[0]);
        assertThat(findOscpSigningCertificate(ocspResponse), is(empty()));

        given(ocspResponse.getCerts()).willReturn(new X509CertificateHolder[] {mock(X509CertificateHolder.class)});
        assertThat(findOscpSigningCertificate(ocspResponse), is(empty()));
    }

    @Test
    void findsSigningCertificateInOcspResponse() throws Exception {
        BasicOCSPResp ocspResponse = new OcspResult(URI.create("ocsp.ca.com"), 200, OcspResponses.REVOKED).getResponseObject();
        Optional<X509Certificate> signingCertificate = findOscpSigningCertificate(ocspResponse);
        assertThat(signingCertificate, not(empty()));
        assertThat(signingCertificate.get().getSubjectDN().getName(), containsString("GlobalSign Domain Validation CA - G2 OCSP responder"));
    }
}
