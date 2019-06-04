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

import java.util.function.Function;

import static no.digipost.security.cert.CertHelper.getOrganizationUnits;
import static no.digipost.security.cert.OcspDecision.LOOKUP_OCSP;
import static no.digipost.security.cert.OcspDecision.NO_OCSP;
import static no.digipost.security.ocsp.OcspUtils.findOcspResponderUrl;


public enum OcspPolicy implements Function<TrustedCertificateAndIssuer, OcspDecision> {

    ALWAYS_DO_OCSP_LOOKUP(trusted -> LOOKUP_OCSP),
    ALWAYS_DO_OCSP_LOOKUP_EXCEPT_DIGIPOST_ISSUED(trusted -> {
        if (getOrganizationUnits(trusted.issuer).anyMatch("Digipost"::equals) && !findOcspResponderUrl(trusted.certificate).isPresent()) {
            return NO_OCSP;
        } else {
            return LOOKUP_OCSP;
        }
    }),
    NEVER_DO_OCSP_LOOKUP(certPath -> NO_OCSP),
    ;


    private final Function<TrustedCertificateAndIssuer, OcspDecision> ocspDecisionResolver;

    OcspPolicy(Function<TrustedCertificateAndIssuer, OcspDecision> ocspDecisionResolver) {
        this.ocspDecisionResolver = ocspDecisionResolver;
    }

    @Override
    public OcspDecision apply(TrustedCertificateAndIssuer certPath) {
        return ocspDecisionResolver.apply(certPath);
    }
}
