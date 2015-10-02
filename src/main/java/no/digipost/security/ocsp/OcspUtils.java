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

import no.digipost.security.X509;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.stream.Stream;

public final class OcspUtils {

    private static final Logger LOG = LoggerFactory.getLogger(OcspUtils.class);

    private static final DLSequence ASN1_OCSP_SIGNING = new DLSequence(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.9"));

    private static final ASN1ObjectIdentifier ASN1_EXTENDED_KEY_USAGE = new ASN1ObjectIdentifier("2.5.29.37");


    public static Optional<X509Certificate> findOscpSigningCertificate(BasicOCSPResp basix) {
        if (basix.getCerts() != null && basix.getCerts().length > 0) {
            Optional<X509Certificate> ocspSigningCertificate = Stream.of(basix.getCerts())
                .filter(cert -> Optional.of(cert)
                    .map(X509CertificateHolder::getExtensions)
                    .map(exts -> exts.getExtension(ASN1_EXTENDED_KEY_USAGE))
                    .map(Extension::getParsedValue)
                    .map(ASN1Encodable::toASN1Primitive)
                    .filter(ASN1_OCSP_SIGNING::equals)
                    .isPresent())
                .map(X509::getCertificateFromHolder)
                .findFirst();

            if (!ocspSigningCertificate.isPresent()) {
                LOG.warn("OCSP response contained certificates, but none of them have OCSP signing extended key usage (identifier {})", ASN1_EXTENDED_KEY_USAGE.getId());
            }
            return ocspSigningCertificate;
        } else {
            return Optional.empty();
        }
    }


    private OcspUtils() {}

}
