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

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static no.digipost.security.X509.findOrganisasjonsnummer;
import static no.digipost.security.cert.CertificatesForTesting.BUYPASS_SEID_2_CERT;
import static no.digipost.security.cert.CertificatesForTesting.DIFI;
import static no.digipost.security.cert.CertificatesForTesting.DIGIPOST_VIRKSOMHETSSERTIFIKAT;
import static no.digipost.security.cert.CertificatesForTesting.EBOKS;
import static no.digipost.security.cert.CertificatesForTesting.EBOKS_COMMFIDES;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static uk.co.probablyfine.matchers.Java8Matchers.where;

public class X509Test {

    @Test
    public void findOrganisasjonsnummerInRealPublicCertificates() {
        assertThat(orgnr(DIGIPOST_VIRKSOMHETSSERTIFIKAT), is("984661185"));
        assertThat(orgnr(DIFI), is("991825827"));
        assertThat(orgnr(EBOKS), is("996460320"));
        assertThat(orgnr(EBOKS_COMMFIDES), is("958935420"));
    }


    @Test
    public void findOrganisasjonsnummerInCommonName() {
        X509Certificate cert = mock(X509Certificate.class, RETURNS_DEEP_STUBS);
        given(cert.getSubjectDN().getName()).willReturn("CN=123456789 acb, O=MyCorp");
        assertThat(findOrganisasjonsnummer(cert).get(), is("123456789"));
    }

    @Test
    public void findOrganisasjonsnummerInSubjectWithoutPrefix() {
        X509Certificate cert = mock(X509Certificate.class, RETURNS_DEEP_STUBS);
        given(cert.getSubjectDN().getName()).willReturn("OID.2.5.4.97=123456789, CN=MyCorp Fullname, OU=MyCorp Department, O=MyCorp, C=NO");
        assertThat(findOrganisasjonsnummer(cert).get(), is("123456789"));
    }

    @Test
    public void doesNotFindOrganisasjonsnummer() {
        X509Certificate cert = mock(X509Certificate.class, RETURNS_DEEP_STUBS);
        given(cert.getSubjectDN().getName()).willReturn("garbage");
        assertThat(findOrganisasjonsnummer(cert), is(Optional.empty()));
    }

    @Test
    public void getOrgNumberBuypassSeid2Cert() {
        assertThat(X509.findOrganisasjonsnummer(BUYPASS_SEID_2_CERT), where(Optional::get, is("100101688")));
    }

    private String orgnr(String certificate) {
        X509Certificate cert = DigipostSecurity.readCertificate(certificate.getBytes());
        return findOrganisasjonsnummer(cert).get();

    }
}
