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

import no.digipost.security.FilesAndDirs;
import no.digipost.security.HttpClient;
import no.digipost.security.ocsp.OcspHttpClientMockitoHelper;
import no.digipost.security.ocsp.OcspLookup;
import no.digipost.security.ocsp.OcspResponses;
import no.digipost.security.ocsp.OcspResult;
import no.digipost.time.ControllableClock;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.util.Encodable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;

import static java.util.Optional.ofNullable;
import static no.digipost.DiggExceptions.applyUnchecked;
import static no.digipost.security.cert.CertStatus.OK;
import static no.digipost.security.cert.CertStatus.REVOKED;
import static no.digipost.security.cert.CertStatus.UNDECIDED;
import static no.digipost.security.cert.CertStatus.UNTRUSTED;
import static no.digipost.security.cert.CertificateValidatorConfig.MOST_STRICT;
import static no.digipost.security.cert.CertificatesForTesting.BUYPASS_SEID_2_CERT;
import static no.digipost.security.cert.CertificatesForTesting.BUYPASS_SEID_2_E_SEAL_CERT;
import static no.digipost.security.cert.CertificatesForTesting.digipostTestRotsertifikat;
import static no.digipost.security.cert.CertificatesForTesting.digipostUtstedtTestsertifikat;
import static no.digipost.security.cert.CertificatesForTesting.digipostVirksomhetsTestsertifikat;
import static no.digipost.security.cert.CertificatesForTesting.digipostVirksomhetssertifikat;
import static no.digipost.security.cert.OcspPolicy.ALWAYS_DO_OCSP_LOOKUP_EXCEPT_DIGIPOST_ISSUED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.quicktheories.QuickTheory.qt;
import static org.quicktheories.generators.SourceDSL.integers;

@ExtendWith(MockitoExtension.class)
class CertificateValidatorTest {

    private CertificateValidator prodValidator;
    private CertificateValidator qaValidator;

    private final ControllableClock clock = ControllableClock.freezedAt(LocalDateTime.of(2020, 2, 24, 12, 5));
    private final TrustFactory trustFactory = new TrustFactory(clock);
    private final Trust prodTrust = trustFactory.seid1.buypassAndCommfidesEnterpriseCertificates();
    private final Trust qaTrust = Trust.merge(prodTrust, Trust.merge(
            trustFactory.seid1.buypassAndCommfidesTestEnterpriseCertificates(),
            trustFactory.seid2.buypassTestEnterpriseCertificates()));

    private final OcspHttpClientMockitoHelper ocsp;

    CertificateValidatorTest(@Mock CloseableHttpClient httpClient) {
        this.ocsp = new OcspHttpClientMockitoHelper(httpClient);
    }

    @BeforeEach
    void stubHttpClientAndInitCertificateValidator() throws Exception {
        prodValidator = new CertificateValidator(MOST_STRICT, prodTrust, ocsp.httpClient);
        qaValidator = new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED), qaTrust, ocsp.httpClient);
    }


    @Test
    void doesntTrustOtherCertificatesButX509() {
        Certificate nonX509Certificate = mock(Certificate.class);
        assertThat(prodValidator.validateCert(nonX509Certificate), is(UNTRUSTED));
        assertThat(qaValidator.validateCert(nonX509Certificate), is(UNTRUSTED));
    }

    @Test
    void qaCertificatesAreUntrustedInProduction() {
        assertThat(prodValidator.validateCert(digipostVirksomhetsTestsertifikat()), is(UNTRUSTED));
    }

    @Test
    void prodCertificatesAreTrusted() throws Exception {
        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp-url"), 200, OcspResponses.OK_OLD));

        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        assertThat(qaValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
    }


    @Test
    void ocspLookupReturningAnythingButStatus200IsUndecidedForProductionAndOKForOtherEnvironments() {
        qt()
            .forAll(integers().between(100, 599))
            .assuming(code -> code != 200)
            .checkAssert(otherThan200 -> {
                ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), otherThan200, null));

                assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
                assertThat(qaValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
            });
    }


    @Test
    void undecidedOcspLookupsAreCachedForOneMinute() throws Exception {
        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 500, null));

        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        ocsp.verifyOcspLookupRequest(times(1));

        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 200, OcspResponses.OK_OLD));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        ocsp.verifyNoMoreRequests();

        clock.timePasses(Duration.ofMinutes(1));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        ocsp.verifyOcspLookupRequest(times(2));
    }



    @Test
    void undecidedOcspLookupWillUseOldOkResponseForUpTo48Hours() {
        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 200, OcspResponses.OK_OLD));

        prodValidator.validateCert(digipostVirksomhetssertifikat());
        prodValidator.validateCert(digipostVirksomhetssertifikat());
        prodValidator.validateCert(digipostVirksomhetssertifikat());
        ocsp.verifyOcspLookupRequest(times(1));


        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 500, null));

        clock.timePasses(Duration.ofMinutes(59));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        ocsp.verifyOcspLookupRequest(times(2));

        clock.timePasses(Duration.ofHours(47));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));

        clock.timePasses(Duration.ofHours(48));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
    }

    @Test
    void revokedCertificate() {
        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 200, OcspResponses.REVOKED));

        assertThat(new CertificateValidator(MOST_STRICT
                .ignoreCustomSigningCertificatesInOcspResponses()
                .validateOcspResponseSignatureUsing((resp, cert) -> true), prodTrust, ocsp.httpClient)
                .validateCert(digipostVirksomhetssertifikat()), is(REVOKED));
    }

    @Test
    void cachesRevokedStatusForever() {
        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 200, OcspResponses.REVOKED));

        CertificateValidator validator = new CertificateValidator(MOST_STRICT
                .ignoreCustomSigningCertificatesInOcspResponses()
                .validateOcspResponseSignatureUsing((resp, cert) -> true),
                prodTrust, ocsp.httpClient);
        assertThat(validator.validateCert(digipostVirksomhetssertifikat()), is(REVOKED));
        ocsp.verifyOcspLookupRequest(times(1));

        clock.timePasses(Duration.ofSeconds(59));
        assertThat(validator.validateCert(digipostVirksomhetssertifikat()), is(REVOKED));
        clock.timePasses(Duration.ofHours(1));
        assertThat(validator.validateCert(digipostVirksomhetssertifikat()), is(REVOKED));
        clock.timePasses(Duration.ofDays(4));
        assertThat(validator.validateCert(digipostVirksomhetssertifikat()), is(REVOKED));
        clock.timePasses(Duration.ofDays(365 * 100));
        assertThat(validator.validateCert(digipostVirksomhetssertifikat()), is(REVOKED));

        ocsp.verifyNoMoreRequests();
    }

    @Test
    void unknownCertificateFromOcspIsUndecidedInProductionAndOkForQA() {
        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 200, OcspResponses.UNKNOWN));

        assertThat(new CertificateValidator(MOST_STRICT
                .ignoreCustomSigningCertificatesInOcspResponses()
                .validateOcspResponseSignatureUsing((resp, cert) -> true), prodTrust, ocsp.httpClient)
                .validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED)
                .ignoreCustomSigningCertificatesInOcspResponses()
                .validateOcspResponseSignatureUsing((resp, cert) -> true), qaTrust, ocsp.httpClient)
                .validateCert(digipostVirksomhetssertifikat()), is(OK));
    }

    @Test
    void malformedResponseFromOcspResponerIsUndecidedInProductionAndOkForQA() {
        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 200, new byte[0]));

        assertThat(new CertificateValidator(MOST_STRICT
                .validateOcspResponseSignatureUsing((resp, cert) -> true), prodTrust, ocsp.httpClient)
                .validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED)
                .validateOcspResponseSignatureUsing((resp, cert) -> true), qaTrust, ocsp.httpClient)
                .validateCert(digipostVirksomhetssertifikat()), is(OK));

    }

    @Test
    void signatureVerificationFailureIsUndecidedInProductionAndOkForQA() throws Exception {
        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 200, OcspResponses.OK_OLD));

        assertThat(new CertificateValidator(MOST_STRICT
                .validateOcspResponseSignatureUsing((resp, cert) -> false),
                prodTrust, ocsp.httpClient)
                .validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED)
                .validateOcspResponseSignatureUsing((resp, cert) -> false),
                qaTrust, ocsp.httpClient)
                .validateCert(digipostVirksomhetssertifikat()), is(OK));
    }

    @Test
    void failingOcspHttpRequestResultsInUndecided() {
        CloseableHttpClient brokenHttp = mock(CloseableHttpClient.class, (Answer<?>) (v -> {throw new SocketTimeoutException("timed out");}));

        assertThat(new CertificateValidator(prodTrust, brokenHttp).validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED), qaTrust, brokenHttp).validateCert(digipostVirksomhetssertifikat()), is(OK));
    }


    @Test
    void alreadyKnownCertificatesIsOkEvenOnFailingOcspHttpRequest() throws Exception {
        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 200, OcspResponses.OK_OLD));

        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        assertThat(qaValidator.validateCert(digipostVirksomhetsTestsertifikat()), is(OK));

        ocsp.whenExecutingOcspLookupRequest().thenThrow(new SocketTimeoutException("timed out"));
        clock.timePasses(Duration.ofHours(6));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(OK));
        assertThat(qaValidator.validateCert(digipostVirksomhetsTestsertifikat()), is(OK));

        clock.timePasses(Duration.ofDays(5));
        assertThat(prodValidator.validateCert(digipostVirksomhetssertifikat()), is(UNDECIDED));
        assertThat(qaValidator.validateCert(digipostVirksomhetsTestsertifikat()), is(OK));
    }

    @Test
    void skipOcspForDigipostIssuedCertificate() throws Exception {
        Trust trust = Trust.merge(qaTrust, Trust.in(clock, digipostTestRotsertifikat()));

        CertificateValidator skipOcspForDigipostCert = new CertificateValidator(
                MOST_STRICT.withOcspPolicy(ALWAYS_DO_OCSP_LOOKUP_EXCEPT_DIGIPOST_ISSUED),
                trust, ocsp.httpClient);

        X509Certificate digipostCertWithoutOcspResponderUrl = digipostUtstedtTestsertifikat();

        assertThat(skipOcspForDigipostCert.validateCert(digipostCertWithoutOcspResponderUrl), is(OK));
        ocsp.verifyNeverAnyRequests();

        CertificateValidator alwaysOcspValidator = new CertificateValidator(
                MOST_STRICT.ignoreCustomSigningCertificatesInOcspResponses().validateOcspResponseSignatureUsing((ocspResponse, issuer) -> true),
                trust, ocsp.httpClient);

        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 200, OcspResponses.REVOKED));

        assertThat(alwaysOcspValidator.validateCert(digipostCertWithoutOcspResponderUrl), is(UNDECIDED));
        ocsp.verifyNeverAnyRequests();

        X509Certificate dpVirksomhetsSertifikat = digipostVirksomhetsTestsertifikat();
        assertThat(alwaysOcspValidator.validateCert(dpVirksomhetsSertifikat), is(REVOKED));

    }

    @Test
    void validateBuypassSeid2Cert() throws IOException {
        ControllableClock clockForValidSeid2Certs = ControllableClock.freezedAt(LocalDateTime.of(2021, 8, 24, 12, 5));
        Trust qaTrustForValidSeid2Certs = new TrustFactory(clockForValidSeid2Certs).seid2.buypassTestEnterpriseCertificates();
        CertificateValidator validator = new CertificateValidator(MOST_STRICT.allowOcspResults(UNDECIDED), qaTrustForValidSeid2Certs, ocsp.httpClient);

        ocsp.whenExecutingOcspLookupRequest().thenReturn(new OcspResult(URI.create("ocsp.ca.com"), 200, OcspResponses.OK_SEID2_BUYPASS));

        assertThat(validator.validateCert(BUYPASS_SEID_2_CERT), is(OK));
        assertThat(validator.validateCert(BUYPASS_SEID_2_E_SEAL_CERT), is(OK));
    }

    private static final Logger LOG = LoggerFactory.getLogger(CertificateValidatorTest.class);

    @Test
    @Disabled("use this to do an actual OCSP-lookup to store the response")
    void doRealOcspLookup() throws Exception {


        try (CloseableHttpClient realClient = HttpClient.create()) {
            X509Certificate certificate = CertificatesForTesting.revoked();
            X509Certificate issuer = CertificatesForTesting.revokedIssuer();

            byte[] response = new TrustedCertificateAndIssuer(certificate, issuer)
                    .ocspLookupRequest
                    .map(OcspLookup::new)
                    .map(l -> l.executeUsing(realClient))
                    .map(ocspResult -> applyUnchecked(Encodable::getEncoded, ocspResult.getResponseObject()))
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
