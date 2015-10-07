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

import java.security.Principal;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

public class DigipostSecurityTest {

    @Rule
    public final ExpectedException expectedException = ExpectedException.none();

    @Test
    public void readOneCertificate() {
        X509Certificate digipostCert = DigipostSecurity.readCertificate("digipost.no-certchain.pem");
        Principal subject = digipostCert.getSubjectDN();
        assertThat(subject.getName(), containsString("POSTEN NORGE AS"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void readAChainOfCertificatesFromOnePem() {
        Stream<String> certs = DigipostSecurity.readCertificates("digipost.no-certchain.pem").map(c -> c.getSubjectDN().getName());
        assertThat(certs.collect(toList()), contains(containsString("POSTEN NORGE AS"), any(String.class), containsString("VeriSign")));
    }

    @Test
    public void describeCertPathAndCertificateAreNullSafe() {
        DigipostSecurity.describe((CertPath) null);
        DigipostSecurity.describe((Certificate) null);
    }

    @Test
    public void failFastCastingOfX509Certificate() {
        expectedException.expect(IllegalCertificateType.class);
        DigipostSecurity.requireX509(mock(Certificate.class));
    }
}
