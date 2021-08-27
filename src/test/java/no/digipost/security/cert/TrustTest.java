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
package no.digipost.security.cert;

import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import static java.time.ZoneOffset.UTC;
import static java.util.stream.Collectors.toSet;
import static no.digipost.security.cert.CertificatesForTesting.BUYPASS_SEID_2_CERT;
import static no.digipost.security.cert.CertificatesForTesting.digipostVirksomhetsTestsertifikat;
import static no.digipost.security.cert.CertificatesForTesting.digipostVirksomhetssertifikat;
import static no.digipost.security.cert.ProdEnvCertificates.buypassClass3Ca3;
import static no.digipost.security.cert.ProdEnvCertificates.buypassClass3RootCa;
import static no.digipost.security.cert.ProdEnvCertificates.commfidesCa;
import static no.digipost.security.cert.ProdEnvCertificates.commfidesRootCa;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.co.probablyfine.matchers.Java8Matchers.where;
import static uk.co.probablyfine.matchers.Java8Matchers.whereNot;

class TrustTest {

    private static final Clock clockSetWhenCertificatesAreValid = Clock.fixed(LocalDateTime.of(2020, 2, 10, 12, 0).toInstant(UTC), UTC);
    private static final TrustFactory trustFactory = new TrustFactory(clockSetWhenCertificatesAreValid);

    private final Trust trust = trustFactory.seid1.buypassAndCommfidesEnterpriseCertificates();


    @Test
    void detects_trust_achors_and_intermediate_certificates() {
        assertThat(trust, where(Trust::getTrustAnchorCertificates, containsInAnyOrder(buypassClass3RootCa(), commfidesRootCa())));
        assertAll("intermediate certs",
                () -> assertThat(trust, where(Trust::getTrustedIntermediateCertificates, hasEntry(is(buypassClass3Ca3().getSubjectX500Principal()), contains(buypassClass3Ca3())))),
                () -> assertThat(trust, where(Trust::getTrustedIntermediateCertificates, hasEntry(is(commfidesCa().getSubjectX500Principal()), contains(commfidesCa())))),
                () -> assertThat(trust, where(Trust::getTrustedIntermediateCertificates, aMapWithSize(2)))
                );
    }

    @Test
    void must_contain_trust_anchors_for_intermediate_certificates() {
        MissingTrustAnchorException missingAnchorsForAll =
                assertThrows(MissingTrustAnchorException.class, () -> Trust.in(clockSetWhenCertificatesAreValid, buypassClass3Ca3(), commfidesCa()));
        assertThat(missingAnchorsForAll.getCertificates(), containsInAnyOrder(buypassClass3Ca3(), commfidesCa()));


        MissingTrustAnchorException missingBuypassRoot =
                assertThrows(MissingTrustAnchorException.class, () -> Trust.in(clockSetWhenCertificatesAreValid, commfidesRootCa(), buypassClass3Ca3(), commfidesCa()));
        assertThat(missingBuypassRoot.getCertificates(), contains(buypassClass3Ca3()));
    }



    @Test
    void returns_only_trust_anchors_when_no_intermediates_match_the_principal() {
        X500Principal randomUnknownPrincipal = digipostVirksomhetsTestsertifikat().getIssuerX500Principal();
        Set<X509Certificate> allCerts = trust.getTrustAnchorsAndAnyIntermediateCertificatesFor(randomUnknownPrincipal).collect(toSet());
        assertThat(allCerts, containsInAnyOrder(buypassClass3RootCa(), commfidesRootCa()));
    }

    @Test
    void returns_trust_anchors_and_trusted_intermediate_certificates() {
        X500Principal digipostCertificateIssuer = digipostVirksomhetssertifikat().getIssuerX500Principal();
        Set<X509Certificate> allCerts = trust.getTrustAnchorsAndAnyIntermediateCertificatesFor(digipostCertificateIssuer).collect(toSet());
        assertThat(allCerts, containsInAnyOrder(buypassClass3RootCa(), commfidesRootCa(), buypassClass3Ca3()));
    }


    @Test
    void builds_keystore_with_certificates() throws KeyStoreException {
        Collection<X509Certificate> certificates = trust.getTrustAnchorCertificates();
        assertThat(certificates, hasSize(greaterThan(0)));

        KeyStore keystore = trust.getTrustAnchorsKeyStore();

        assertThat(keystore.aliases(), where(Collections::list, hasSize(certificates.size())));
        for (String alias : Collections.list(keystore.aliases())) {
            assertTrue(keystore.isCertificateEntry(alias));
        }
    }


    @Test
    void resolve_cert_path_from_certificate() {
        ReviewedCertPath reviewedPath = trust.resolveCertPath(digipostVirksomhetssertifikat());
        assertThat(reviewedPath, where(ReviewedCertPath::isTrusted));
        assertThat(reviewedPath.getPath(), where(CertPath::getCertificates, hasSize(2)));
    }

    @Test
    void resolve_cert_path_from_seid2_certificate() {
        Clock clockForValidSeid2Certs = Clock.fixed(LocalDateTime.of(2021, 8, 24, 12, 5).toInstant(UTC), UTC);
        ReviewedCertPath certPath = new TrustFactory(clockForValidSeid2Certs).seid2.buypassTestEnterpriseCertificates().resolveCertPath(BUYPASS_SEID_2_CERT);
        assertThat(certPath, where(ReviewedCertPath::isTrusted));
    }


    @Test
    void cert_path_of_qa_certificate_is_not_trusted_in_production() {
        ReviewedCertPath reviewedPath = trust.resolveCertPath(digipostVirksomhetsTestsertifikat());

        assertThat(reviewedPath, whereNot(ReviewedCertPath::isTrusted));
        Exception thrown = assertThrows(Exception.class, reviewedPath::getPath);
        assertThat(thrown, where(Exception::getMessage, containsString("unable to find valid certification path")));
    }

    @Test
    void trust_equality() {
        EqualsVerifier.forClass(Trust.class)
            .withPrefabValues(X509Certificate.class, buypassClass3RootCa(), commfidesRootCa())
            .withPrefabValues(X500Principal.class, buypassClass3RootCa().getSubjectX500Principal(), commfidesCa().getSubjectX500Principal())
            .verify();
    }


    @Nested
    class Merging {

        @Test
        void trusts_with_different_clocks_is_not_possible() {
            Trust trust1 = Trust.in(Clock.fixed(Instant.ofEpochSecond(1_234_567), UTC));
            Trust trust2 = Trust.in(Clock.fixed(Instant.ofEpochSecond(9_000_000), UTC));
            assertThrows(NonMatchingClocksException.class, () -> Trust.merge(trust1, trust2));
        }

        @Test
        void trusts_with_no_overlapping_certificates() {
            Trust buypassTrust = trustFactory.seid1.buypassEnterpriseCertificates();
            Trust commfidesTrust = trustFactory.seid1.commfidesEnterpriseCertificates();
            Trust merged = Trust.merge(buypassTrust, commfidesTrust);
            assertThat(merged, equalTo(Trust.in(clockSetWhenCertificatesAreValid, buypassClass3RootCa(), buypassClass3Ca3(), commfidesRootCa(), commfidesCa())));
        }

        @Test
        void trusts_with_some_overlapping_certificates() {
            Trust buypassAndCommfidesRootTrust = Trust.in(clockSetWhenCertificatesAreValid, buypassClass3RootCa(), buypassClass3Ca3(), commfidesRootCa());
            Trust commfidesTrust = Trust.in(clockSetWhenCertificatesAreValid, commfidesRootCa(), commfidesCa());
            Trust merged = Trust.merge(buypassAndCommfidesRootTrust, commfidesTrust);
            assertThat(merged, equalTo(trust));
        }

    }

}
