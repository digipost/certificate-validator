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
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Stream;

import static co.unruly.matchers.Java8Matchers.where;
import static co.unruly.matchers.Java8Matchers.whereNot;
import static java.util.stream.Collectors.toSet;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TrustTest {

    private final X509Certificate buypassRoot = DigipostSecurity.readCertificate("sertifikater/prod/BPClass3RootCA.cer");
    private final X509Certificate buypassIntermediate = DigipostSecurity.readCertificate("sertifikater/prod/BPClass3CA3.cer");
    private final X509Certificate commfidesRoot = DigipostSecurity.readCertificate("sertifikater/prod/commfides_root_ca.cer");
    private final X509Certificate commfidesIntermediate = DigipostSecurity.readCertificate("sertifikater/prod/commfides_ca.cer");

    private final Trust trust = new Trust(Stream.of(buypassRoot, commfidesRoot), Stream.of(buypassIntermediate, commfidesIntermediate));

    @Test
    public void returns_only_trust_anchors_when_no_intermediates_match_the_principal() {
        X500Principal randomUnknownPrincipal = Certificates.digipostVirksomhetsTestsertifikat().getIssuerX500Principal();
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
        assertThat(certificates, hasSize(greaterThan(0)));

        KeyStore keystore = trust.getTrustAnchorsKeyStore();

        assertThat(keystore.aliases(), where(Collections::list, hasSize(certificates.size())));
        for (String alias : Collections.list(keystore.aliases())) {
            assertTrue(keystore.isCertificateEntry(alias));
        }
    }


    @Test
    public void resolve_cert_path_from_certificate() {
        ReviewedCertPath reviewedPath = trust.resolveCertPath(Certificates.digipostVirksomhetssertifikat());
        assertThat(reviewedPath, where(ReviewedCertPath::isTrusted));
        assertThat(reviewedPath.getPath(), where(CertPath::getCertificates, hasSize(2)));
    }

    @Test
    public void cert_path_of_qa_certificate_is_not_trusted_in_production() {
        ReviewedCertPath reviewedPath = trust.resolveCertPath(Certificates.digipostVirksomhetsTestsertifikat());

        assertThat(reviewedPath, whereNot(ReviewedCertPath::isTrusted));
        Exception thrown = assertThrows(Exception.class, reviewedPath::getPath);
        assertThat(thrown, where(Exception::getMessage, containsString("unable to find valid certification path")));
    }

}
