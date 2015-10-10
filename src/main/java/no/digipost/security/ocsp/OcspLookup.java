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

import no.digipost.security.Sha1Calculator;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Optional;

import static no.digipost.exceptions.Exceptions.mayThrow;
import static no.digipost.exceptions.Exceptions.rethrowAnyException;
import static org.apache.http.client.methods.RequestBuilder.post;

/**
 * <strong>Online Certificate Status Protocol (OCSP)</strong> is an automated certificate checking
 * network protocol. One can query an OCSP responder for the status of a certificate. The responder
 * returns whether the certificate is still trusted by the CA that issued it.
 *
 * @see <a href="http://tools.ietf.org/html/rfc6960">Internet Engineering Task Force (IETF) RFC6960</a>
 */
public final class OcspLookup {

    static final String AUTHORITY_INFO_ACCESS_OID = "1.3.6.1.5.5.7.1.1";

    private static final Logger LOG = LoggerFactory.getLogger(OcspLookup.class);


    /**
     * Prepare a new OCSP lookup request for the given certificate.
     *
     * @param certificate the certificate to lookup. It must contain an OCSP responder URI.
     * @param issuer the issuer of the certificate.
     * @return an OCSP request, ready to be {@link OcspLookup#executeUsing(CloseableHttpClient) executed},
     *         or {@link Optional#empty()} of no OCSP responder URI was found, or any other error occuring.
     */
    public static Optional<OcspLookup> newLookup(X509Certificate certificate, X509Certificate issuer) {
        return Optional.ofNullable(certificate.getExtensionValue(AUTHORITY_INFO_ACCESS_OID))

            .flatMap(mayThrow((byte[] data) -> {
                DEROctetString base = (DEROctetString) ASN1Primitive.fromByteArray(data);
                DLSequence seq = (DLSequence) ASN1Primitive.fromByteArray(base.getOctets());
                Enumeration<?> objects = seq.getObjects();
                while (objects.hasMoreElements()) {
                    Object elm = objects.nextElement();
                    if (elm instanceof DLSequence) {
                        ASN1Encodable id = ((DLSequence)elm).getObjectAt(0);
                        if (OCSPObjectIdentifiers.id_pkix_ocsp.equals(id)) {
                            DERTaggedObject dt = (DERTaggedObject)((DLSequence)elm).getObjectAt(1);
                            DEROctetString dos =  (DEROctetString)dt.getObjectParser(dt.getTagNo(), true);
                            return new String(dos.getOctets());
                        }
                    }
                }
                throw new OCSPException("Object identifier " + OCSPObjectIdentifiers.id_pkix_ocsp + " not found");

            }).ifException(exception -> { LOG.warn("Failed to extract OCSP uri from " + certificate, exception); }))

            .flatMap(mayThrow((String uri) -> {
                CertificateID certificateId = new CertificateID(new Sha1Calculator(), new X509CertificateHolder(issuer.getEncoded()), certificate.getSerialNumber());
                return new OcspLookup(uri, certificateId);

            }).ifException(exception -> { LOG.warn("Failed to create certificate ID from issuer " + issuer + " and certificate " + certificate, exception); }));
    }



    public final String uri;
    public final CertificateID certificateId;

    private OcspLookup(String uri, CertificateID certificateId) {
        this.certificateId = certificateId;
        this.uri = uri;
    }

    /**
     * Execute the OCSP lookup request.
     *
     * @param client the http client to use for executing the lookup request.
     * @return the {@link OcspResult result} of the OCSP lookup.
     */
    public OcspResult executeUsing(CloseableHttpClient client) {
        return Optional.of(new OCSPReqBuilder().addRequest(certificateId))
            .flatMap(mayThrow((OCSPReqBuilder b) -> b.build()).ifException(rethrowAnyException))
            .flatMap(mayThrow(OCSPReq::getEncoded).ifException(rethrowAnyException))
            .map(requestEntity -> post()
                                  .setUri(uri)
                                  .addHeader("Content-Type", "application/ocsp-request")
                                  .setEntity(new ByteArrayEntity(requestEntity)).build())
            .flatMap(mayThrow((HttpUriRequest r) -> client.execute(r)).ifException(rethrowAnyException))
            .map(response -> new OcspResult(uri, response))
            .get();
    }

    @Override
    public String toString() {
        return "OCSP-lookup to responder uri " + uri;
    }

}
