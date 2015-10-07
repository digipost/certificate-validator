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

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toMap;

/**
 * Reasons for revoking a certificate, as specified in RFC5280:
 * <a href="https://tools.ietf.org/html/rfc5280#page-69">tools.ietf.org/html/rfc5280#page-69</a>
 */
public enum RevocationReason {

    unspecified             (0),
    keyCompromise           (1),
    cACompromise            (2),
    affiliationChanged      (3),
    superseded              (4),
    cessationOfOperation    (5),
    certificateHold         (6),
    unused                  (7),
    removeFromCRL           (8),
    privilegeWithdrawn      (9),
    aACompromise            (10),

    UNKNOWN                 (Integer.MIN_VALUE, r -> "unknown reason");

    private static final Map<Integer, RevocationReason> byCode = Stream.of(values()).filter(r -> r != UNKNOWN).collect(toMap(r -> r.code, r -> r));


    public final int code;
    private final String textualDescription;

    RevocationReason(int reasonCode) {
        this(reasonCode, r -> r.name() + " (" + r.code + ")");
    }

    private RevocationReason(int reasonCode, Function<RevocationReason, String> textualDescription) {
        this.code = reasonCode;
        this.textualDescription = textualDescription.apply(this);
    }

    public static RevocationReason resolve(int code) {
        return byCode.getOrDefault(code, UNKNOWN);
    }

    @Override
    public String toString() {
        return textualDescription;
    }
}
