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

import com.google.common.io.ByteStreams;
import com.pholser.junit.quickcheck.Property;
import com.pholser.junit.quickcheck.generator.InRange;
import com.pholser.junit.quickcheck.runner.JUnitQuickcheck;
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
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.mockito.stubbing.Answer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
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
import static no.digipost.security.cert.CertStatus.*;
import static no.digipost.security.cert.CertificateValidatorConfig.MOST_STRICT;
import static no.digipost.security.cert.Certificates.digipostTestsertifikat;
import static no.digipost.security.cert.Certificates.digipostVirksomhetssertifikat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@RunWith(JUnitQuickcheck.class)
public class CertificateValidatorTest {

    private static final Trust PROD_TRUST = BuypassCommfidesCertificates.createProdTrust();
    private static final Trust QA_TRUST = BuypassCommfidesCertificates.createTestTrust();

    @Rule
    public final MockitoRule mockito = MockitoJUnit.rule();

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

    private ControllableClock clock = new ControllableClock(LocalDateTime.of(2015, 6, 24, 12, 5));


    @Before
    public void stubHttpClientAndInitCertificateValidator() throws Exception {
        when(response.getStatusLine()).thenReturn(ocspResponseStatus);
        when(response.getEntity()).thenReturn(ocspResponseEntity);
        when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(response);
        when(ocspResponseStatus.toString()).thenAnswer(i -> "status " + ocspResponseStatus.getStatusCode());

        prodValidator = new CertificateValidator(MOST_STRICT, PROD_TRUST, httpClient, clock);
        qaValidator = new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED), QA_TRUST, httpClient, clock);
    }


    @Test
    public void doesntTrustOtherCertificatesButX509() {
        Certificate nonX509Certificate = mock(Certificate.class);
        assertThat(prodValidator.validateCert(nonX509Certificate), is(UNTRUSTED));
        assertThat(qaValidator.validateCert(nonX509Certificate), is(UNTRUSTED));
    }

    @Test
    public void qaCertificatesAreUntrustedInProduction() {
        assertThat(prodValidator.validateCert(digipostTestsertifikat()), is(UNTRUSTED));
    }

    @Test
    public void prodCertificatesAreTrusted() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> OcspResponses.ok());

        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        assertThat(qaValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
    }


    @Property
    public void ocspLookupReturningAnythingButStatus200IsUndecidedForProductionAndOKForOtherEnvironments(@InRange(min="100", max="599") int otherThan200) throws Exception {
        assumeThat(otherThan200, not(200));

        given(ocspResponseStatus.getStatusCode()).willReturn(otherThan200);

        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(qaValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
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
                .validateOcspResponseSignatureUsing((resp, cert) -> true), PROD_TRUST, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(REVOKED));
    }

    @Test
    public void cachesRevokedStatusForever() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> OcspResponses.revoked());

        CertificateValidator validator = new CertificateValidator(MOST_STRICT
                .ignoreCustomSigningCertificatesInOcspResponses()
                .validateOcspResponseSignatureUsing((resp, cert) -> true),
                PROD_TRUST, httpClient, clock);
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
                .validateOcspResponseSignatureUsing((resp, cert) -> true), PROD_TRUST, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED)
                .ignoreCustomSigningCertificatesInOcspResponses()
                .validateOcspResponseSignatureUsing((resp, cert) -> true), QA_TRUST, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(OK));
    }

    @Test
    public void malformedResponseFromOcspResponerIsUndecidedInProductionAndOkForQA() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> new ByteArrayInputStream(new byte[0]));

        assertThat(new CertificateValidator(MOST_STRICT
                .validateOcspResponseSignatureUsing((resp, cert) -> true), PROD_TRUST, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED)
                .validateOcspResponseSignatureUsing((resp, cert) -> true), QA_TRUST, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(OK));

    }

    @Test
    public void signatureVerificationFailureIsUndecidedInProductionAndOkForQA() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).willAnswer(i -> OcspResponses.ok());

        assertThat(new CertificateValidator(MOST_STRICT
                .validateOcspResponseSignatureUsing((resp, cert) -> false),
                PROD_TRUST, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED)
                .validateOcspResponseSignatureUsing((resp, cert) -> false),
                QA_TRUST, httpClient, clock)
                .validateCert(digipostVirksomhetssertifikat()), is(OK));
    }

    @Test
    public void failingOcspHttpRequestResultsInUndecided() {
        CloseableHttpClient brokenHttp = mock(CloseableHttpClient.class, (Answer<?>) (v -> {throw new SocketTimeoutException("timed out");}));

        assertThat(new CertificateValidator(PROD_TRUST, brokenHttp).validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED), QA_TRUST, brokenHttp).validateCert(digipostVirksomhetssertifikat()), is(OK));
    }


    @Test
    public void alreadyKnownCertificatesIsOkEvenOnFailingOcspHttpRequest() throws Exception {
        given(ocspResponseStatus.getStatusCode()).willReturn(200);
        given(ocspResponseEntity.getContent()).will(i -> OcspResponses.ok());

        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        assertThat(qaValidator.validateCert(digipostTestsertifikat()), is(OK));

        given(httpClient.execute(any())).will(v -> {throw new SocketTimeoutException("timed out");});
        given(ocspResponseStatus.getStatusCode()).will(v -> {throw new IllegalStateException("should never be called");});
        clock.timePasses(Duration.ofHours(6));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        assertThat(qaValidator.validateCert(digipostTestsertifikat()), is(OK));

        clock.timePasses(Duration.ofDays(5));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(qaValidator.validateCert(digipostTestsertifikat()), is(OK));
    }






    private static final Logger LOG = LoggerFactory.getLogger(CertificateValidatorTest.class);

    @Test
    @Ignore("use this to do an actual OCSP-lookup to store the response")
    public void doRealOcspLookup() throws Exception {


        try (CloseableHttpClient realClient = HttpClient.create()) {
            X509Certificate certificate = Certificates.revoked();
            X509Certificate issuer = Certificates.revokedIssuer();

            byte[] response = OcspLookup.newLookup(certificate, issuer)
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
