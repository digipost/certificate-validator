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
package no.digipost.security.cert;

import no.digipost.security.DigipostSecurity;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.security.auth.x500.X500Principal;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toSet;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

public class TrustTest {

    private final X509Certificate buypassRoot = DigipostSecurity.readCertificate("sertifikater/prod/BPClass3RootCA.cer");
    private final X509Certificate buypassIntermediate = DigipostSecurity.readCertificate("sertifikater/prod/BPClass3CA3.cer");
    private final X509Certificate commfidesRoot = DigipostSecurity.readCertificate("sertifikater/prod/commfides_root_ca.cer");
    private final X509Certificate commfidesIntermediate = DigipostSecurity.readCertificate("sertifikater/prod/commfides_ca.cer");

    private final Trust trust = new Trust(Stream.of(buypassRoot, commfidesRoot), Stream.of(buypassIntermediate, commfidesIntermediate));

    @Test
    public void returns_only_trust_anchors_when_no_intermediates_match_the_principal() {
        X500Principal randomUnknownPrincipal = Certificates.digipostTestsertifikat().getIssuerX500Principal();
        Set<X509Certificate> allCerts = trust.getTrustAnchorsAndAnyIntermediateCertificatesFor(randomUnknownPrincipal).collect(toSet());
        assertThat(allCerts, containsInAnyOrder(buypassRoot, commfidesRoot));
    }

    @Test
    public void returns_trust_anchors_and_trusted_intermediate_certificates() {
        X500Principal digipostCertificateIssuer = Certificates.digipostVirksomhetssertifikat().getIssuerX500Principal();
        Set<X509Certificate> allCerts = trust.getTrustAnchorsAndAnyIntermediateCertificatesFor(digipostCertificateIssuer).collect(toSet());
        assertThat(allCerts, containsInAnyOrder(buypassRoot, commfidesRoot, buypassIntermediate));
    }



    @Test
    public void builds_keystore_with_certificates() throws KeyStoreException {
        Collection<X509Certificate> certificates = trust.getTrustAnchorCertificates();
        KeyStore keystore = trust.getTrustAnchorsKeyStore();

        assertThat(certificates, hasSize(greaterThan(0)));
        for (X509Certificate certificate : certificates) {
            assertTrue(keystore.isCertificateEntry(certificate.getSubjectDN().toString()));
        }
    }



    @Rule
    public final ExpectedException expectedException = ExpectedException.none();


    @Test
    public void resolve_cert_path_from_certificate() {
        ReviewedCertPath reviewedPath = trust.resolveCertPath(Certificates.digipostVirksomhetssertifikat());
        assertTrue(reviewedPath.isTrusted());
        assertThat(reviewedPath.getPath().getCertificates(), hasSize(2));
    }

    @Test
    public void cert_path_of_qa_certificate_is_not_trusted_in_production() {
        ReviewedCertPath reviewedPath = trust.resolveCertPath(Certificates.digipostTestsertifikat());

        assertFalse(reviewedPath.isTrusted());
        expectedException.expectMessage("unable to find valid certification path");
        reviewedPath.getPath();
    }

}
