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
import no.digipost.time.ControllableClock;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static java.time.ZoneOffset.UTC;
import static java.util.Arrays.asList;
import static no.digipost.security.cert.CertStatus.OK;
import static no.digipost.security.cert.CertStatus.REVOKED;
import static no.digipost.security.cert.CrlChecker.MAX_AGE_OF_DOWNLOADED_CRL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class CrlCheckerTest {

    private static final Instant NOW = Instant.parse("2026-11-13T12:00:00Z");
    private static final TestPki pki = new TestPki(NOW);

    private final ControllableClock clock = ControllableClock.freezedAt(NOW, UTC);

    @Mock
    private CloseableHttpClient httpClient;


    @Test
    void newestUsableProvidedCrlIsUsedWhenNewerCrlsAreNotUsable() {
        // a day and a half ago, the "expired" CRL was current, and the newest CRL was not yet valid
        clock.set(NOW.minus(Duration.ofHours(36)));
        CrlProvider provider = CrlProvider.of(asList(pki.expiredRootCrl(pki.intermediate), pki.rootCrl()));

        assertThat(new CrlChecker(httpClient, clock).check(pki.intermediate, pki.root, provider), is(Optional.of(REVOKED)));
    }

    @Test
    void downloadedCrlIsDownloadedAgainWhenOlderThanMaxAge() throws Exception {
        servingCrl(pki.rootCrl());
        CrlChecker crlChecker = new CrlChecker(httpClient, clock);

        assertThat(crlChecker.check(pki.intermediate, pki.root, CrlProvider.NONE), is(Optional.of(OK)));
        clock.timePasses(MAX_AGE_OF_DOWNLOADED_CRL.minusMinutes(1));
        assertThat(crlChecker.check(pki.intermediate, pki.root, CrlProvider.NONE), is(Optional.of(OK)));
        verify(httpClient, times(1)).execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class));

        clock.timePasses(Duration.ofMinutes(1));
        assertThat(crlChecker.check(pki.intermediate, pki.root, CrlProvider.NONE), is(Optional.of(OK)));
        verify(httpClient, times(2)).execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class));
    }

    @Test
    void downloadedCrlIsUsedUntilNextUpdateWhenNewCrlCanNotBeDownloaded() throws Exception {
        servingCrl(pki.rootCrl(pki.intermediate));
        CrlChecker crlChecker = new CrlChecker(httpClient, clock);
        assertThat(crlChecker.check(pki.intermediate, pki.root, CrlProvider.NONE), is(Optional.of(REVOKED)));

        failingDownload();
        clock.timePasses(MAX_AGE_OF_DOWNLOADED_CRL.multipliedBy(2));
        assertThat(crlChecker.check(pki.intermediate, pki.root, CrlProvider.NONE), is(Optional.of(REVOKED)));
        verify(httpClient, times(2)).execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class));

        clock.set(pki.rootCrl().getNextUpdate().toInstant());
        assertThat(crlChecker.check(pki.intermediate, pki.root, CrlProvider.NONE), is(Optional.empty()));
    }


    private void servingCrl(X509CRL crl) throws Exception {
        doAnswer(invocation -> {
            BasicClassicHttpResponse response = new BasicClassicHttpResponse(200);
            response.setEntity(new ByteArrayEntity(crl.getEncoded(), ContentType.create("application/pkix-crl")));
            return invocation.getArgument(1, HttpClientResponseHandler.class).handleResponse(response);
        }).when(httpClient).execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class));
    }

    private void failingDownload() throws Exception {
        doAnswer(invocation -> invocation.getArgument(1, HttpClientResponseHandler.class).handleResponse(new BasicClassicHttpResponse(404)))
                .when(httpClient).execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class));
    }
}
