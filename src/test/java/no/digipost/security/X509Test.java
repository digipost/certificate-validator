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

import no.digipost.security.cert.Certificates;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static no.digipost.security.X509.findOrganisasjonsnummer;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;

public class X509Test {

    @Test
    public void findOrganisasjonsnummerInRealPublicCertificates() {
        assertThat(orgnr(Certificates.DIGIPOST_VIRKSOMHETSSERTIFIKAT), is("984661185"));
        assertThat(orgnr(Certificates.DIFI), is("991825827"));
        assertThat(orgnr(Certificates.EBOKS), is("996460320"));
        assertThat(orgnr(Certificates.EBOKS_COMMFIDES), is("958935420"));
    }


    @Test
    public void findOrganisasjonsnummerInCommonName() {
        X509Certificate cert = mock(X509Certificate.class, RETURNS_DEEP_STUBS);
        given(cert.getSubjectDN().getName()).willReturn("CN=123456789 acb, O=MyCorp");
        assertThat(findOrganisasjonsnummer(cert).get(), is("123456789"));
    }


    @Test
    public void doesNotFindOrganisasjonsnummer() {
        X509Certificate cert = mock(X509Certificate.class, RETURNS_DEEP_STUBS);
        given(cert.getSubjectDN().getName()).willReturn("garbage");
        assertThat(findOrganisasjonsnummer(cert), is(Optional.empty()));
    }


    private String orgnr(String certificate) {
        X509Certificate cert = DigipostSecurity.readCertificate(certificate.getBytes());
        return findOrganisasjonsnummer(cert).get();

    }
}
