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

import no.digipost.security.crl.CrlProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static java.time.ZoneOffset.UTC;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static no.digipost.security.cert.CertStatus.OK;
import static no.digipost.security.cert.CertStatus.REVOKED;
import static no.digipost.security.cert.CertStatus.UNDECIDED;
import static no.digipost.security.cert.CertStatus.UNTRUSTED;
import static no.digipost.security.cert.CertificateValidatorConfig.MOST_STRICT;
import static no.digipost.security.cert.OcspPolicy.NEVER_DO_OCSP_LOOKUP;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SuppliedChainValidationTest {

    private static final Instant NOW = Instant.parse("2026-11-13T12:00:00Z");
    private static final TestPki pki = new TestPki(NOW);

    /**
     * Revocation of the leaf certificate is not part of these tests, only the supplied intermediate certificates.
     */
    private static final CertificateValidatorConfig CONFIG = MOST_STRICT.withOcspPolicy(NEVER_DO_OCSP_LOOKUP);

    private final Clock clock = Clock.fixed(NOW, UTC);
    private final Trust onlyRoot = Trust.in(clock, pki.root);

    @Mock
    private CloseableHttpClient httpClient;


    @Test
    void untrustedWithoutTheIntermediateCertificate() {
        assertThat(validator(CONFIG).validateCert(pki.leaf), is(UNTRUSTED));
        verifyNoInteractions(httpClient);
    }

    @Test
    void untrustedWhenChainDoesNotLeadToTrustAnchor() {
        TestPki otherPki = new TestPki(NOW);
        assertThat(validator(CONFIG).validateCert(otherPki.leaf, asList(otherPki.intermediate, otherPki.root)), is(UNTRUSTED));
        verifyNoInteractions(httpClient);
    }

    @Test
    void okWhenProvidedCrlDoesNotRevokeIntermediate() {
        CertificateValidator validator = validator(CONFIG.withCrlProvider(CrlProvider.of(singletonList(pki.rootCrl()))));
        assertThat(validator.validateCert(pki.leaf, singletonList(pki.intermediate)), is(OK));
        verifyNoInteractions(httpClient);
    }

    @Test
    void revokedWhenProvidedCrlRevokesIntermediate() {
        CertificateValidator validator = validator(CONFIG.withCrlProvider(CrlProvider.of(singletonList(pki.rootCrl(pki.intermediate)))));
        assertThat(validator.validateCert(pki.leaf, singletonList(pki.intermediate)), is(REVOKED));
    }

    @Test
    void downloadsCrlFromDistributionPointWhenNotProvided() throws Exception {
        servingCrl(pki.rootCrl());
        assertThat(validator(CONFIG).validateCert(pki.leaf, singletonList(pki.intermediate)), is(OK));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<ClassicHttpRequest> request = ArgumentCaptor.forClass(ClassicHttpRequest.class);
        verify(httpClient).execute(request.capture(), any(HttpClientResponseHandler.class));
        assertThat(request.getValue().getUri(), is(TestPki.INTERMEDIATE_CRL_DISTRIBUTION_POINT));
    }

    @Test
    void revokedWhenDownloadedCrlRevokesIntermediate() throws Exception {
        servingCrl(pki.rootCrl(pki.intermediate));
        assertThat(validator(CONFIG).validateCert(pki.leaf, singletonList(pki.intermediate)), is(REVOKED));
    }

    @Test
    void downloadedCrlIsReusedUntilNextUpdate() throws Exception {
        servingCrl(pki.rootCrl());
        CertificateValidator validator = validator(CONFIG);
        X509Certificate otherLeaf = pki.newLeaf();
        assertThat(validator.validateCert(pki.leaf, singletonList(pki.intermediate)), is(OK));
        assertThat(validator.validateCert(otherLeaf, singletonList(pki.intermediate)), is(OK));
        verify(httpClient, times(1)).execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class));
    }

    @Test
    void expiredProvidedCrlFallsBackToDistributionPoint() throws Exception {
        servingCrl(pki.rootCrl(pki.intermediate));
        CertificateValidator validator = validator(CONFIG.withCrlProvider(CrlProvider.of(singletonList(pki.expiredRootCrl()))));
        assertThat(validator.validateCert(pki.leaf, singletonList(pki.intermediate)), is(REVOKED));
    }

    @Test
    void crlWithInvalidSignatureIsNotUsed() {
        CertificateValidator validator = validator(CONFIG.withCrlProvider(CrlProvider.of(singletonList(pki.rootCrlSignedWithWrongKey()))));
        failingDownload();
        assertThat(validator.validateCert(pki.leaf, singletonList(pki.intermediate)), is(UNDECIDED));
    }

    @Test
    void undecidedWhenRevocationStatusOfIntermediateCanNotBeDetermined() throws Exception {
        failingDownload();
        assertThat(validator(CONFIG).validateCert(pki.leaf, singletonList(pki.intermediate)), is(UNDECIDED));
    }

    @Test
    void undecidedIntermediateStatusCanBeAllowedByConfig() throws Exception {
        failingDownload();
        assertThat(validator(CONFIG.allowOcspResults(UNDECIDED)).validateCert(pki.leaf, singletonList(pki.intermediate)), is(OK));
    }

    @Test
    void intermediateCertificatesAlreadyInTrustAreNotChecked() {
        Trust rootAndIntermediate = Trust.in(clock, pki.root, pki.intermediate);
        CertificateValidator validator = new CertificateValidator(CONFIG, rootAndIntermediate, httpClient);
        assertThat(validator.validateCert(pki.leaf, singletonList(pki.intermediate)), is(OK));
        verifyNoInteractions(httpClient);
    }

    @Test
    void cachedResultIsNotReusedForAnotherChain() throws Exception {
        CertificateValidator validator = validator(CONFIG.withCrlProvider(CrlProvider.of(singletonList(pki.rootCrl()))));
        assertThat(validator.validateCert(pki.leaf, singletonList(pki.intermediate)), is(OK));
        assertThat(validator.validateCert(pki.leaf), is(UNTRUSTED));
    }

    @Test
    void validatesTheFirstCertificateOfTheChainAsLeaf() {
        CertificateValidator validator = validator(CONFIG.withCrlProvider(CrlProvider.of(singletonList(pki.rootCrl()))));
        assertThat(validator.validateCertChain(asList(pki.leaf, pki.intermediate)), is(OK));
        assertThat(validator.validateCertChain(singletonList(pki.leaf)), is(UNTRUSTED));
        verifyNoInteractions(httpClient);
    }

    @Test
    void emptyChainIsUntrusted() {
        assertThat(validator(CONFIG).validateCertChain(emptyList()), is(UNTRUSTED));
        verifyNoInteractions(httpClient);
    }

    @Test
    void revokedIntermediateDoesNotRevokeTheLeafForOtherPaths() {
        X509Certificate reissuedIntermediate = pki.intermediateWithOcspResponder();
        CertificateValidator validator = validator(CONFIG.withCrlProvider(CrlProvider.of(singletonList(pki.rootCrl(pki.intermediate)))));
        assertThat(validator.validateCert(pki.leaf, singletonList(pki.intermediate)), is(REVOKED));
        assertThat(validator.validateCert(pki.leaf, singletonList(reissuedIntermediate)), is(OK));
        assertThat(validator.validateCert(pki.leaf, singletonList(pki.intermediate)), is(REVOKED));
    }

    @Test
    void cachedResultIsReusedWhenChainContainsExtraneousCertificates() {
        failingDownload();
        CertificateValidator validator = validator(CONFIG);
        assertThat(validator.validateCert(pki.leaf, singletonList(pki.intermediate)), is(UNDECIDED));
        int httpInvocations = mockingDetails(httpClient).getInvocations().size();

        X509Certificate unrelated = new TestPki(NOW).root;
        assertThat(validator.validateCert(pki.leaf, asList(pki.intermediate, unrelated)), is(UNDECIDED));
        assertThat(mockingDetails(httpClient).getInvocations().size(), is(httpInvocations));
    }


    @Test
    void ocspSigningCertificateChainingThroughTheSuppliedIntermediateDoesNotCauseEndlessRecursion() throws Exception {
        X509Certificate intermediate = pki.intermediateWithOcspResponder();
        X509Certificate ocspSigner = pki.ocspSignerIssuedByIntermediate();
        servingOcspResponse(TestPki.INTERMEDIATE_OCSP_RESPONDER, pki.goodOcspResponse(intermediate, pki.root, ocspSigner, pki.ocspSignerKeys.getPrivate()));
        OcspPolicy ocspOnlyForIntermediate = trusted -> trusted.certificate.equals(pki.leaf) ? OcspDecision.SKIP_OCSP : OcspDecision.LOOKUP_OCSP;

        CertificateValidator validator = validator(MOST_STRICT.withOcspPolicy(ocspOnlyForIntermediate));

        assertThat(validator.validateCert(pki.leaf, singletonList(intermediate)), is(UNDECIDED));
    }

    @Test
    void leafOcspResponseSignedByDelegatedSignerIssuedByTheSuppliedIntermediate() throws Exception {
        X509Certificate intermediate = pki.intermediateWithOcspResponder();
        X509Certificate leaf = pki.leafWithOcspResponder();
        X509Certificate ocspSigner = pki.ocspSignerIssuedByIntermediate();
        Map<URI, byte[]> responses = new HashMap<>();
        responses.put(TestPki.INTERMEDIATE_OCSP_RESPONDER, pki.goodOcspResponse(intermediate, pki.root, pki.root, pki.rootKeys.getPrivate()));
        responses.put(TestPki.LEAF_OCSP_RESPONDER, pki.goodOcspResponse(leaf, intermediate, ocspSigner, pki.ocspSignerKeys.getPrivate()));
        servingOcspResponses(responses);

        assertThat(validator(MOST_STRICT).validateCert(leaf, singletonList(intermediate)), is(OK));
    }

    @Test
    void undecidedIntermediateStatusIsCachedForOtherLeaves() {
        failingDownload();
        CertificateValidator validator = validator(CONFIG);
        assertThat(validator.validateCert(pki.leaf, singletonList(pki.intermediate)), is(UNDECIDED));
        int httpInvocations = mockingDetails(httpClient).getInvocations().size();

        assertThat(validator.validateCert(pki.newLeaf(), singletonList(pki.intermediate)), is(UNDECIDED));
        assertThat(mockingDetails(httpClient).getInvocations().size(), is(httpInvocations));
    }


    private CertificateValidator validator(CertificateValidatorConfig config) {
        return new CertificateValidator(config, onlyRoot, httpClient);
    }

    private void servingCrl(X509CRL crl) throws Exception {
        when(httpClient.execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class))).thenAnswer(invocation -> {
            BasicClassicHttpResponse response = new BasicClassicHttpResponse(200);
            response.setEntity(new ByteArrayEntity(crl.getEncoded(), ContentType.create("application/pkix-crl")));
            return invocation.getArgument(1, HttpClientResponseHandler.class).handleResponse(response);
        });
    }

    private void servingOcspResponse(URI responder, byte[] ocspResponse) throws Exception {
        servingOcspResponses(singletonMap(responder, ocspResponse));
    }

    /**
     * Serves the given OCSP responses, and 404 for any other request.
     */
    private void servingOcspResponses(Map<URI, byte[]> ocspResponses) throws Exception {
        when(httpClient.execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class))).thenAnswer(invocation -> {
            byte[] ocspResponse = ocspResponses.get(invocation.getArgument(0, ClassicHttpRequest.class).getUri());
            BasicClassicHttpResponse response;
            if (ocspResponse != null) {
                response = new BasicClassicHttpResponse(200);
                response.setEntity(new ByteArrayEntity(ocspResponse, ContentType.create("application/ocsp-response")));
            } else {
                response = new BasicClassicHttpResponse(404);
            }
            return invocation.getArgument(1, HttpClientResponseHandler.class).handleResponse(response);
        });
    }

    private void failingDownload() {
        try {
            when(httpClient.execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class))).thenAnswer(invocation ->
                    invocation.getArgument(1, HttpClientResponseHandler.class).handleResponse(new BasicClassicHttpResponse(404)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
