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
package no.digipost.security.ocsp;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.mockito.Mockito;
import org.mockito.stubbing.OngoingStubbing;
import org.mockito.verification.VerificationMode;

import static no.digipost.DiggExceptions.getUnchecked;
import static no.digipost.DiggExceptions.runUnchecked;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public final class OcspHttpClientMockitoHelper {

    public final CloseableHttpClient httpClient;

    public OcspHttpClientMockitoHelper(CloseableHttpClient httpClient) {
        if (!mockingDetails(httpClient).isMock()) {
            throw new IllegalArgumentException(
                    "http client must be a Mockito mock, but got instance of " + httpClient.getClass().getName());
        }
        this.httpClient = httpClient;
    }

    public OngoingStubbing<OcspResult> whenExecutingOcspLookupRequest() {
        return getUnchecked(() -> when(httpClient.execute(any(), Mockito.<HttpClientResponseHandler<OcspResult>>any())));
    }

    public void verifyOcspLookupRequest(VerificationMode verification) {
        runUnchecked(() -> verify(httpClient, verification).execute(any(), Mockito.<HttpClientResponseHandler<OcspResult>>any()));
    }

    public void verifyNeverAnyRequests() {
        verifyNoInteractions(httpClient);
    }

    public void verifyNoMoreRequests() {
        verifyNoMoreInteractions(httpClient);
    }
}
