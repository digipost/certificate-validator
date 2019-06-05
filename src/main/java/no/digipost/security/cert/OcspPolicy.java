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

import java.util.function.Predicate;

import static no.digipost.security.cert.OcspDecision.LOOKUP_OCSP;
import static no.digipost.security.cert.OcspDecision.SKIP_OCSP;

@FunctionalInterface
public interface OcspPolicy {

    final OcspPolicy ALWAYS_DO_OCSP_LOOKUP = always(LOOKUP_OCSP);

    final OcspPolicy NEVER_DO_OCSP_LOOKUP = always(SKIP_OCSP);

    final OcspPolicy ALWAYS_DO_OCSP_LOOKUP_EXCEPT_DIGIPOST_ISSUED =
            ALWAYS_DO_OCSP_LOOKUP.except(trusted -> trusted.isIssuedByDigipostCA() && !trusted.ocspLookupRequest.isPresent(), SKIP_OCSP);

    /**
     * Create a policy which <em>always</em> makes the given {@link OcspDecision decision}.
     *
     * @return the {@link OcspPolicy}
     */
    static OcspPolicy always(OcspDecision decision) {
        return trustedCertAndIssuer -> decision;
    }


    /**
     * Evaluate the given <em>trusted</em> {@link TrustedCertificateAndIssuer certificate and its issuer's certificate}
     * if an OCSP-lookup should be performed.
     *
     * @param trustedCertificateAndIssuer the certificate and its issuer's certificate
     * @return the resulting {@link OcspDecision}.
     */
    OcspDecision decideFor(TrustedCertificateAndIssuer trustedCertificateAndIssuer);


    /**
     * Create a new policy which yields another {@link OcspDecision result} for a certain case,
     * or else yields what this policy would originally yield.
     *
     * @param trustedCertEvaluator the evaluator function for identifying if the given {@code decisionResult}
     *                             should be the result of the new policy.
     * @param decisionResult       the decision to yield if the {@code trustedCertEvaluator} yields {@code true}.
     * @return the new {@link OcspPolicy policy}
     */
    default OcspPolicy except(Predicate<TrustedCertificateAndIssuer> trustedCertEvaluator, OcspDecision decisionResult) {
        return trusted -> trustedCertEvaluator.test(trusted) ? decisionResult : decideFor(trusted);
    }
}
