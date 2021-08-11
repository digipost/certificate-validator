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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static com.google.common.io.ByteStreams.toByteArray;
import static no.digipost.DiggBase.nonNull;

public final class OcspResponses {

    private static final byte[] OK_OLD;
    private static final byte[] UNKNOWN;
    private static final byte[] REVOKED;
    private static final byte[] OK_SEID2_BUYPASS;

    static {
        try {
            OK_OLD = toByteArray(nonNull("/ocsp/ok.response", OcspResponses.class::getResourceAsStream));
            UNKNOWN = toByteArray(nonNull("/ocsp/unknown.response", OcspResponses.class::getResourceAsStream));
            REVOKED = toByteArray(nonNull("/ocsp/revoked.response", OcspResponses.class::getResourceAsStream));

            OK_SEID2_BUYPASS = toByteArray(nonNull("/ocsp/ok_seid2_buypass.response", OcspResponses.class::getResourceAsStream));
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public static InputStream ok() {
        return new ByteArrayInputStream(OK_OLD);
    }

    public static InputStream okSeid2Buypass() {
        return new ByteArrayInputStream(OK_SEID2_BUYPASS);
    }

    public static InputStream unknown() {
        return new ByteArrayInputStream(UNKNOWN);
    }

    public static InputStream revoked() {
        return new ByteArrayInputStream(REVOKED);
    }

    private OcspResponses() {}

}
