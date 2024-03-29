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

import no.digipost.security.DigipostSecurity;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Optional;
import java.util.stream.Stream;

import static no.digipost.security.DigipostSecurity.describe;

public final class OcspUtils {

    private static final Logger LOG = LoggerFactory.getLogger(OcspUtils.class);

    private static final ASN1Sequence ASN1_OCSP_SIGNING = new DERSequence(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.9"));

    private static final ASN1ObjectIdentifier ASN1_EXTENDED_KEY_USAGE = new ASN1ObjectIdentifier("2.5.29.37");

    private static final String AUTHORITY_INFO_ACCESS_OID = "1.3.6.1.5.5.7.1.1";


    public static Optional<URI> findOcspResponderUrl(X509Certificate certificate) {
        byte[] authorityInfoAccessValue = certificate.getExtensionValue(AUTHORITY_INFO_ACCESS_OID);
        if (authorityInfoAccessValue == null) {
            return Optional.empty();
        }
        try {
            ASN1OctetString base = (ASN1OctetString) ASN1Primitive.fromByteArray(authorityInfoAccessValue);
            ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(base.getOctets());
            @SuppressWarnings("unchecked")
            Enumeration<ASN1Encodable> objects = seq.getObjects();
            while (objects.hasMoreElements()) {
                ASN1Encodable elm = objects.nextElement();
                if (elm instanceof ASN1Sequence) {
                    ASN1Encodable id = ((ASN1Sequence)elm).getObjectAt(0);
                    if (OCSPObjectIdentifiers.id_pkix_ocsp.equals(id)) {
                        ASN1TaggedObject dt = (ASN1TaggedObject)((DLSequence)elm).getObjectAt(1);
                        ASN1OctetString dos =  ASN1OctetString.getInstance(dt, dt.isExplicit());
                        return Optional.of(URI.create(new String(dos.getOctets())));
                    }
                }
            }
            LOG.warn("Failed to extract OCSP uri from " + describe(certificate) + ", because Object identifier " + OCSPObjectIdentifiers.id_pkix_ocsp + " not found");
            return Optional.empty();
        } catch (Exception e) {
            LOG.warn(
                    "Error when trying to find Object identifier " + OCSPObjectIdentifiers.id_pkix_ocsp + " to extract OCSP uri from " + describe(certificate) + ": " +
                    e.getClass().getSimpleName() + " - '" + e.getMessage() + "'", e);
            return Optional.empty();
        }
    }


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
                .map(OcspUtils::getCertificateFromHolder)
                .findFirst();

            if (!ocspSigningCertificate.isPresent()) {
                LOG.warn("OCSP response contained certificates, but none of them have OCSP signing extended key usage (identifier {})", ASN1_EXTENDED_KEY_USAGE.getId());
            }
            return ocspSigningCertificate;
        } else {
            return Optional.empty();
        }
    }


    private static final JcaX509CertificateConverter JCA_X509_CERTIFICATE_CONVERTER = new JcaX509CertificateConverter().setProvider(DigipostSecurity.PROVIDER_NAME);

    static final X509Certificate getCertificateFromHolder(X509CertificateHolder holder) {
        try {
            return JCA_X509_CERTIFICATE_CONVERTER.getCertificate(holder);
        } catch (CertificateException e) {
            throw new RuntimeException(
                    "Error retrieving " + X509Certificate.class.getName() +
                    " from BouncyCastle " + X509CertificateHolder.class.getSimpleName() + ". " +
                    "Reason: " + e.getMessage(), e);
        }
    }

    private OcspUtils() {}


    static Optional<CertificateID> tryCreateCertificateId(X509Certificate certificate, X509Certificate issuer) {
        try {
            return Optional.of(new CertificateID(new Sha1Calculator(), new JcaX509CertificateHolder(issuer), certificate.getSerialNumber()));
        } catch (OCSPException | CertificateEncodingException e) {
            OcspLookupRequest.LOG.warn("Failed to create certificate ID from certificate: {}, issued by {}", describe(certificate), describe(issuer), e);
            return Optional.empty();
        }
    }

}
