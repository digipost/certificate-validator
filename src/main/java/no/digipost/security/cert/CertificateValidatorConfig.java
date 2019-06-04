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

import java.util.EnumSet;
import java.util.Set;
import java.util.function.Predicate;

import static java.util.Collections.unmodifiableSet;
import static no.digipost.security.cert.CertStatus.OK;
import static no.digipost.security.cert.OcspSetting.ALWAYS_DO_OCSP;

/**
 * Configuration of a {@link CertificateValidator}. Use {@link #MOST_STRICT} to acquire
 * a configuration instance, and optionally use it to customize into a new configuration.
 */
public class CertificateValidatorConfig {

    /**
     * This is the most strict validator, and the only way to initially acquire an instance of {@link CertificateValidatorConfig}.
     * If required, e.g. for test purposes, you may loosen the strictness by using methods as
     * {@link #doOcspWhen(Predicate)} or {@link #allowOcspResults(CertStatus...)}.
     */
    public static final CertificateValidatorConfig MOST_STRICT =
            new CertificateValidatorConfig(ALWAYS_DO_OCSP, EnumSet.of(OK), OcspSignatureValidator.DEFAULT, false);

    final Predicate<ReviewedCertPath> shouldDoOcsp;

    private final Set<CertStatus> allowedOcspResults;

    final OcspSignatureValidator ocspSignatureValidator;
    final boolean ignoreCustomSigningCertificatesInOcspResponses;

    public boolean allowsOcspResult(CertStatus status) {
        return allowedOcspResults.contains(status);
    }

    private CertificateValidatorConfig(
            Predicate<ReviewedCertPath> shouldDoOcsp,
            Set<CertStatus> allowedOcspResults,
            OcspSignatureValidator ocspSignatureValidator,
            boolean ignoreCustomSigningCertificatesInOcspResponses) {

        this.shouldDoOcsp = shouldDoOcsp;
        this.allowedOcspResults = unmodifiableSet(allowedOcspResults);
        this.ocspSignatureValidator = ocspSignatureValidator;
        this.ignoreCustomSigningCertificatesInOcspResponses = ignoreCustomSigningCertificatesInOcspResponses;
    }

    public CertificateValidatorConfig doOcspWhen(Predicate<ReviewedCertPath> shouldDoOcsp) {
        return new CertificateValidatorConfig(shouldDoOcsp, allowedOcspResults, ocspSignatureValidator, ignoreCustomSigningCertificatesInOcspResponses);
    }

    public CertificateValidatorConfig allowOcspResults(CertStatus ... allowedOcspResults) {
        return new CertificateValidatorConfig(shouldDoOcsp, EnumSet.of(OK, allowedOcspResults), ocspSignatureValidator, ignoreCustomSigningCertificatesInOcspResponses);
    }

    CertificateValidatorConfig validateOcspResponseSignatureUsing(OcspSignatureValidator ocspSignatureValidator) {
        return new CertificateValidatorConfig(shouldDoOcsp, allowedOcspResults, ocspSignatureValidator, ignoreCustomSigningCertificatesInOcspResponses);
    }

    CertificateValidatorConfig ignoreCustomSigningCertificatesInOcspResponses() {
        return new CertificateValidatorConfig(shouldDoOcsp, allowedOcspResults, ocspSignatureValidator, true);
    }

}
