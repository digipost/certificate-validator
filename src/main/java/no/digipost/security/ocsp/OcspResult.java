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

import no.digipost.security.DigipostSecurityException;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;

import java.net.URI;

/**
 * The result of a successful lookup against an OCSP responder.
 * The entity from the response is retrieved using {@link #getResponseObject()}.
 *
 * @see BasicOCSPResp
 */
public final class OcspResult {

    public final URI uri;
    private final byte[] response;
    private final int responseStatusCode;

    public OcspResult(URI uri, int responseStatusCode, byte[] response) {
        this.uri = uri;
        this.responseStatusCode = responseStatusCode;
        this.response = response;
    }


    /**
     * @return a BasicOCSPResp
     */
    public BasicOCSPResp getResponseObject() {
        BasicOCSPResp responseObject;
        try {
            OCSPResp oresp = new OCSPResp(response);
            responseObject = (BasicOCSPResp) oresp.getResponseObject();
        } catch (Exception e) {
            throw new DigipostSecurityException(
                    "Error obtaining a " + BasicOCSPResp.class.getName() + " " +
                    "from the response of " + this, e);
        }
        if (responseObject == null) {
            throw new DigipostSecurityException(
                    "OCSP result of " + this + " contained a null response. " +
                    "This may be a problem with the certificate issuer");
        }
        return responseObject;
    }

    /**
     * @return whether the http status code from the request was OK.
     */
    public boolean isOkResponse() {
        return responseStatusCode == 200;
    }

    /**
     * @return the actual response body from the OCSP responder as raw bytes
     */
    public byte[] getRawResponse() {
        return response;
    }

    @Override
    public String toString() {
        return "OCSP result from " + uri + " HTTP status " + responseStatusCode;
    }



}
