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

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.security.cert.X509Certificate;

@FunctionalInterface
public interface OcspSignatureValidator {

    public static final OcspSignatureValidator DEFAULT = (ocspResponse, issuer) -> {
        ContentVerifierProvider contentVerifierProvider;
        try {
            contentVerifierProvider = new JcaContentVerifierProviderBuilder().build(issuer);
        } catch (OperatorCreationException e) {
            throw new OCSPException(e.getMessage(), e);
        }
        return ocspResponse.isSignatureValid(contentVerifierProvider);
    };

    boolean isValidSignature(BasicOCSPResp ocspResponse, X509Certificate issuer) throws OCSPException;

}
