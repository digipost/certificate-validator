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

import com.google.common.io.ByteStreams;
import no.digipost.security.FilesAndDirs;
import no.digipost.security.HttpClient;
import no.digipost.security.ocsp.OcspLookup;
import no.digipost.security.ocsp.OcspResponses;
import no.digipost.security.ocsp.OcspResult;
import no.digipost.time.ControllableClock;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;

import static java.util.Optional.ofNullable;
import static no.digipost.DiggIO.autoClosing;
import static no.digipost.security.cert.BuypassCommfidesCertificates.createTestTrustWithAdditionalCerts;
import static no.digipost.security.cert.CertStatus.OK;
import static no.digipost.security.cert.CertStatus.REVOKED;
import static no.digipost.security.cert.CertStatus.UNDECIDED;
import static no.digipost.security.cert.CertStatus.UNTRUSTED;
import static no.digipost.security.cert.CertificateValidatorConfig.MOST_STRICT;
import static no.digipost.security.cert.Certificates.BUYPASS_SEID_2_CERT;
import static no.digipost.security.cert.Certificates.BUYPASS_SEID_2_E_SEAL_CERT;
import static no.digipost.security.cert.Certificates.BUYPASS_SEID_2_ISSUER;
import static no.digipost.security.cert.Certificates.digipostTestRotsertifikat;
import static no.digipost.security.cert.Certificates.digipostUtstedtTestsertifikat;
import static no.digipost.security.cert.Certificates.digipostVirksomhetsTestsertifikat;
import static no.digipost.security.cert.Certificates.digipostVirksomhetssertifikat;
import static no.digipost.security.cert.OcspPolicy.ALWAYS_DO_OCSP_LOOKUP_EXCEPT_DIGIPOST_ISSUED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.quicktheories.QuickTheory.qt;
import static org.quicktheories.generators.SourceDSL.integers;

@ExtendWith(MockitoExtension.class)
public class CertificateValidatorTest {

    @Mock
    private CloseableHttpClient httpClient;

    @Mock
    private CloseableHttpResponse response;

    @Mock
    private StatusLine ocspResponseStatus;

    @Mock
    private HttpEntity ocspResponseEntity;


    private CertificateValidator prodValidator;
    private CertificateValidator qaValidator;

    private final ControllableClock clock = ControllableClock.freezedAt(LocalDateTime.of(2020, 2, 24, 12, 5));
    private final Trust prodTrust = BuypassCommfidesCertificates.createProdTrust(clock);
    private final Trust qaTrust = BuypassCommfidesCertificates.createTestTrust(clock);


    @BeforeEach
    public void stubHttpClientAndInitCertificateValidator() throws Exception {
        lenient().when(response.getStatusLine()).thenReturn(ocspResponseStatus);
        lenient().when(response.getEntity()).thenReturn(ocspResponseEntity);
        lenient().when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(response);
        lenient().when(ocspResponseStatus.toString()).thenAnswer(i -> "status " + ocspResponseStatus.getStatusCode());

        prodValidator = new CertificateValidator(MOST_STRICT, prodTrust, httpClient, clock);
        qaValidator = new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED), qaTrust, httpClient, clock);
    }


    @Test
    public void doesntTrustOtherCertificatesButX509() {
        Certificate nonX509Certificate = mock(Certificate.class);
        assertThat(prodValidator.validateCert(nonX509Certificate), is(UNTRUSTED));
        assertThat(qaValidator.validateCert(nonX509Certificate), is(UNTRUSTED));
    }

    @Test
    public void qaCertificatesAreUntrustedInProduction() {
        assertThat(prodValidator.validateCert(digipostVirksomhetsTestsertifikat()), is(UNTRUSTED));
    }

    @Test
    public void prodCertificatesAreTrusted() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> OcspResponses.ok());

        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        assertThat(qaValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
    }


    @Test
    public void ocspLookupReturningAnythingButStatus200IsUndecidedForProductionAndOKForOtherEnvironments() {
        qt()
            .forAll(integers().between(100, 599))
            .assuming(code -> code != 200)
            .checkAssert(otherThan200 -> {
                lenient().when(ocspResponseStatus.getStatusCode()).thenReturn(otherThan200);

                assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
                assertThat(qaValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
                verify(ocspResponseStatus, times(2)).getStatusCode();
            });
    }


    @Test
    public void undecidedOcspLookupsAreCachedForOneMinute() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(500);

        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        verify(httpClient, times(1)).execute(any());

        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> OcspResponses.ok());
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        verifyNoMoreInteractions(httpClient);

        clock.timePasses(Duration.ofMinutes(1));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        verify(httpClient, times(2)).execute(any());
    }



    @Test
    public void undecidedOcspLookupWillUseOldOkResponseForUpTo48Hours() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> OcspResponses.ok());

        prodValidator.validateCert(digipostVirksomhetssertifikat());
        prodValidator.validateCert(digipostVirksomhetssertifikat());
        prodValidator.validateCert(digipostVirksomhetssertifikat());
        verify(httpClient, times(1)).execute(any());


        given(ocspResponseStatus.getStatusCode()).willReturn(500);

        clock.timePasses(Duration.ofMinutes(59));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        verify(httpClient, times(2)).execute(any());

        clock.timePasses(Duration.ofHours(47));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));

        clock.timePasses(Duration.ofHours(48));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
    }

    @Test
    public void revokedCertificate() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> OcspResponses.revoked());

        assertThat(new CertificateValidator(MOST_STRICT
                .ignoreCustomSigningCertificatesInOcspResponses()
                .validateOcspResponseSignatureUsing((resp, cert) -> true), prodTrust, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(REVOKED));
    }

    @Test
    public void cachesRevokedStatusForever() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> OcspResponses.revoked());

        CertificateValidator validator = new CertificateValidator(MOST_STRICT
                .ignoreCustomSigningCertificatesInOcspResponses()
                .validateOcspResponseSignatureUsing((resp, cert) -> true),
                prodTrust, httpClient, clock);
        assertThat(validator.validateCert(digipostVirksomhetssertifikat()), is(REVOKED));
        verify(httpClient, times(1)).execute(any());

        clock.timePasses(Duration.ofSeconds(59));
        assertThat(validator.validateCert(digipostVirksomhetssertifikat()), is(REVOKED));
        clock.timePasses(Duration.ofHours(1));
        assertThat(validator.validateCert(digipostVirksomhetssertifikat()), is(REVOKED));
        clock.timePasses(Duration.ofDays(4));
        assertThat(validator.validateCert(digipostVirksomhetssertifikat()), is(REVOKED));
        clock.timePasses(Duration.ofDays(365 * 100));
        assertThat(validator.validateCert(digipostVirksomhetssertifikat()), is(REVOKED));

        verifyNoMoreInteractions(httpClient);
    }

    @Test
    public void unknownCertificateFromOcspIsUndecidedInProductionAndOkForQA() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> OcspResponses.unknown());

        assertThat(new CertificateValidator(MOST_STRICT
                .ignoreCustomSigningCertificatesInOcspResponses()
                .validateOcspResponseSignatureUsing((resp, cert) -> true), prodTrust, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED)
                .ignoreCustomSigningCertificatesInOcspResponses()
                .validateOcspResponseSignatureUsing((resp, cert) -> true), qaTrust, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(OK));
    }

    @Test
    public void malformedResponseFromOcspResponerIsUndecidedInProductionAndOkForQA() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> new ByteArrayInputStream(new byte[0]));

        assertThat(new CertificateValidator(MOST_STRICT
                .validateOcspResponseSignatureUsing((resp, cert) -> true), prodTrust, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED)
                .validateOcspResponseSignatureUsing((resp, cert) -> true), qaTrust, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(OK));

    }

    @Test
    public void signatureVerificationFailureIsUndecidedInProductionAndOkForQA() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> OcspResponses.ok());

        assertThat(new CertificateValidator(MOST_STRICT
                .validateOcspResponseSignatureUsing((resp, cert) -> false),
                prodTrust, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED)
                .validateOcspResponseSignatureUsing((resp, cert) -> false),
                qaTrust, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(OK));
    }

    @Test
    public void failingOcspHttpRequestResultsInUndecided() {
        CloseableHttpClient brokenHttp = mock(CloseableHttpClient.class, (Answer<?>) (v -> {throw new SocketTimeoutException("timed out");}));

        assertThat(new CertificateValidator(prodTrust, brokenHttp).validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED), qaTrust, brokenHttp).validateCert(digipostVirksomhetssertifikat()), is(OK));
    }


    @Test
    public void alreadyKnownCertificatesIsOkEvenOnFailingOcspHttpRequest() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).will(i -> OcspResponses.ok());

        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        assertThat(qaValidator.validateCert(digipostVirksomhetsTestsertifikat()), is(OK));

        given(httpClient.execute(any())).will(v -> {throw new SocketTimeoutException("timed out");});
        lenient().when(ocspResponseStatus.getStatusCode()).then(v -> {throw new IllegalStateException("should never be called");});
        clock.timePasses(Duration.ofHours(6));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        assertThat(qaValidator.validateCert(digipostVirksomhetsTestsertifikat()), is(OK));

        clock.timePasses(Duration.ofDays(5));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(qaValidator.validateCert(digipostVirksomhetsTestsertifikat()), is(OK));
    }

    @Test
    public void skipOcspForDigipostIssuedCertificate() throws Exception {
        Trust trust = createTestTrustWithAdditionalCerts(clock, digipostTestRotsertifikat());

        CertificateValidator skipOcspForDigipostCert = new CertificateValidator(
                MOST_STRICT.withOcspPolicy(ALWAYS_DO_OCSP_LOOKUP_EXCEPT_DIGIPOST_ISSUED),
                trust, httpClient, clock);

        X509Certificate digipostCertWithoutOcspResponderUrl = digipostUtstedtTestsertifikat();

        assertThat(skipOcspForDigipostCert.validateCert(digipostCertWithoutOcspResponderUrl), is(OK));
        verifyNoInteractions(httpClient);

        CertificateValidator alwaysOcspValidator = new CertificateValidator(
                MOST_STRICT.ignoreCustomSigningCertificatesInOcspResponses().validateOcspResponseSignatureUsing((ocspResponse, issuer) -> true),
                trust, httpClient, clock);

        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).will(i -> OcspResponses.revoked());

        assertThat(alwaysOcspValidator.validateCert(digipostCertWithoutOcspResponderUrl), is(UNDECIDED));

        verifyNoInteractions(httpClient);
        verifyNoInteractions(ocspResponseEntity);

        X509Certificate dpVirksomhetsSertifikat = digipostVirksomhetsTestsertifikat();
        assertThat(alwaysOcspValidator.validateCert(dpVirksomhetsSertifikat), is(REVOKED));

    }

    @Test
    public void validateBuypassSeid2Cert() throws IOException {
        CertificateValidator validator = new CertificateValidator(MOST_STRICT, QA_TRUST, httpClient, clock);

        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).will(i -> OcspResponses.okSeid2Buypass());

        assertThat(validator.validateCert(BUYPASS_SEID_2_CERT), is(OK));
        assertThat(validator.validateCert(BUYPASS_SEID_2_E_SEAL_CERT), is(OK));
    }

    private static final Logger LOG = LoggerFactory.getLogger(CertificateValidatorTest.class);

    @Test
    @Disabled("use this to do an actual OCSP-lookup to store the response")
    public void doRealOcspLookup() throws Exception {


        try (CloseableHttpClient realClient = HttpClient.create()) {
            X509Certificate certificate = BUYPASS_SEID_2_CERT;
            X509Certificate issuer = BUYPASS_SEID_2_ISSUER;

            byte[] response = new TrustedCertificateAndIssuer(certificate, issuer)
                    .ocspLookupRequest
                    .map(OcspLookup::new)
                    .map(l -> l.executeUsing(realClient))
                    .map(autoClosing((OcspResult res) -> ByteStreams.toByteArray(res.response.getEntity().getContent())))
                    .get();

            BasicOCSPResp ocspResp = (BasicOCSPResp) new OCSPResp(response).getResponseObject();
            for (SingleResp singleResp : ocspResp.getResponses()) {
                LOG.info("got {}", ofNullable(singleResp.getCertStatus()).map(r -> r.getClass().getSimpleName()).orElse("GOOD"));
            }

            Path responseDir = FilesAndDirs.newWorkDir("ocsp");
            Files.createDirectories(responseDir);
            Path ocspOutputFile = responseDir.resolve(Paths.get("ocsp.response"));
            Files.write(ocspOutputFile, response);
            LOG.info("Written OCSP-response to {}", ocspOutputFile);
        }
    }

}
