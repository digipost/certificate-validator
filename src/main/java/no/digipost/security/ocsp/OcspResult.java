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
package no.digipost.security.ocsp;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;

import java.io.Closeable;
import java.io.IOException;

/**
 * The result of a successful lookup against an OCSP responder.
 * The entity from the response is retrieved using {@link #getResponseObject()}.
 *
 * @see BasicOCSPResp
 */
public final class OcspResult implements Closeable {

    public final String uri;
    public final CloseableHttpResponse response;

    OcspResult(String uri, CloseableHttpResponse response) {
        this.uri = uri;
        this.response = response;
    }


    /**
     * @return a BasicOCSPResp
     */
    public BasicOCSPResp getResponseObject() throws OCSPException, IllegalStateException, IOException {
        OCSPResp oresp = new OCSPResp(response.getEntity().getContent());
        return (BasicOCSPResp) oresp.getResponseObject();
    }

    /**
     * @return whether the http status code from the request was OK.
     */
    public boolean isOkResponse() {
        return response.getStatusLine().getStatusCode() == 200;
    }

    @Override
    public void close() throws IOException {
        response.close();
    }
}
