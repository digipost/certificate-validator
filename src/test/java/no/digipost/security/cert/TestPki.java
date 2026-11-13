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
package no.digipost.security.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import static java.util.Arrays.asList;

/**
 * Generates a small PKI for testing: a root CA, an intermediate CA issued by the root,
 * and a leaf certificate issued by the intermediate CA, as well as CRLs.
 */
final class TestPki {

    static final URI INTERMEDIATE_CRL_DISTRIBUTION_POINT = URI.create("http://crl.example.test/root.crl");
    static final URI INTERMEDIATE_OCSP_RESPONDER = URI.create("http://ocsp.example.test/root");
    static final URI LEAF_OCSP_RESPONDER = URI.create("http://ocsp.example.test/intermediate");

    private static final AtomicLong SERIAL = new AtomicLong(1000);

    final KeyPair rootKeys = generateKeyPair();
    final KeyPair intermediateKeys = generateKeyPair();
    final KeyPair leafKeys = generateKeyPair();
    final KeyPair ocspSignerKeys = generateKeyPair();

    final X509Certificate root;
    final X509Certificate intermediate;
    final X509Certificate leaf;

    private final Instant now;

    TestPki(Instant now) {
        this.now = now;
        X500Name rootName = new X500Name("CN=Test Root CA, O=Test");
        X500Name intermediateName = new X500Name("CN=Test Intermediate CA, O=Test");
        this.root = certificate(rootName, rootName, rootKeys, rootKeys.getPrivate(), true, null);
        this.intermediate = certificate(intermediateName, rootName, intermediateKeys, rootKeys.getPrivate(), true, INTERMEDIATE_CRL_DISTRIBUTION_POINT);
        this.leaf = certificate(new X500Name("CN=Test Leaf, O=Test"), intermediateName, leafKeys, intermediateKeys.getPrivate(), false, null);
    }


    X509Certificate newLeaf() {
        return certificate(new X500Name("CN=Another Test Leaf, O=Test"), X500Name.getInstance(intermediate.getSubjectX500Principal().getEncoded()),
                leafKeys, intermediateKeys.getPrivate(), false, null);
    }


    /**
     * The same intermediate CA (same name and key) as {@link #intermediate}, but with an OCSP responder URL.
     */
    X509Certificate intermediateWithOcspResponder() {
        return certificate(X500Name.getInstance(intermediate.getSubjectX500Principal().getEncoded()), X500Name.getInstance(root.getSubjectX500Principal().getEncoded()),
                intermediateKeys, rootKeys.getPrivate(), true, INTERMEDIATE_CRL_DISTRIBUTION_POINT, ocspResponder(INTERMEDIATE_OCSP_RESPONDER));
    }

    /**
     * The same leaf (same name and key) as {@link #leaf}, but with an OCSP responder URL.
     */
    X509Certificate leafWithOcspResponder() {
        return certificate(X500Name.getInstance(leaf.getSubjectX500Principal().getEncoded()), X500Name.getInstance(intermediate.getSubjectX500Principal().getEncoded()),
                leafKeys, intermediateKeys.getPrivate(), false, null, ocspResponder(LEAF_OCSP_RESPONDER));
    }

    private static Consumer<X509v3CertificateBuilder> ocspResponder(URI responder) {
        return builder -> {
            try {
                builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(new AccessDescription(
                        AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, responder.toString()))));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    /**
     * An OCSP signing certificate issued by the <em>intermediate</em> CA.
     */
    X509Certificate ocspSignerIssuedByIntermediate() {
        return certificate(new X500Name("CN=Test OCSP Signer, O=Test"), X500Name.getInstance(intermediate.getSubjectX500Principal().getEncoded()),
                ocspSignerKeys, intermediateKeys.getPrivate(), false, null, builder -> {
                    try {
                        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    /**
     * An OCSP response with status GOOD for the given certificate, signed by and embedding the given signer certificate.
     */
    byte[] goodOcspResponse(X509Certificate certificate, X509Certificate issuer, X509Certificate signer, PrivateKey signerKey) {
        try {
            X509CertificateHolder issuerHolder = new X509CertificateHolder(issuer.getEncoded());
            X509CertificateHolder signerHolder = new X509CertificateHolder(signer.getEncoded());
            CertificateID id = new CertificateID(new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1), issuerHolder, certificate.getSerialNumber());
            BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(new RespID(signerHolder.getSubject()));
            builder.addResponse(id, CertificateStatus.GOOD);
            return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL,
                    builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(signerKey), new X509CertificateHolder[] { signerHolder }, Date.from(now)))
                    .getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    X509CRL rootCrl(X509Certificate ... revoked) {
        return crl(root, rootKeys.getPrivate(), now.minus(Duration.ofHours(1)), now.plus(Duration.ofDays(1)), revoked);
    }

    X509CRL expiredRootCrl(X509Certificate ... revoked) {
        return crl(root, rootKeys.getPrivate(), now.minus(Duration.ofDays(2)), now.minus(Duration.ofDays(1)), revoked);
    }

    X509CRL rootCrlSignedWithWrongKey(X509Certificate ... revoked) {
        return crl(root, intermediateKeys.getPrivate(), now.minus(Duration.ofHours(1)), now.plus(Duration.ofDays(1)), revoked);
    }

    X509CRL intermediateCrl(X509Certificate ... revoked) {
        return crl(intermediate, intermediateKeys.getPrivate(), now.minus(Duration.ofHours(1)), now.plus(Duration.ofDays(1)), revoked);
    }


    private X509CRL crl(X509Certificate issuer, PrivateKey signingKey, Instant thisUpdate, Instant nextUpdate, X509Certificate ... revoked) {
        try {
            X509v2CRLBuilder builder = new X509v2CRLBuilder(X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()), Date.from(thisUpdate));
            builder.setNextUpdate(Date.from(nextUpdate));
            for (X509Certificate cert : asList(revoked)) {
                builder.addCRLEntry(cert.getSerialNumber(), Date.from(thisUpdate), CRLReason.keyCompromise);
            }
            return new JcaX509CRLConverter().getCRL(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(signingKey)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private X509Certificate certificate(X500Name subject, X500Name issuer, KeyPair subjectKeys, PrivateKey issuerKey, boolean ca, URI crlDistributionPoint) {
        return certificate(subject, issuer, subjectKeys, issuerKey, ca, crlDistributionPoint, builder -> {});
    }

    private X509Certificate certificate(X500Name subject, X500Name issuer, KeyPair subjectKeys, PrivateKey issuerKey, boolean ca, URI crlDistributionPoint, Consumer<X509v3CertificateBuilder> extraExtensions) {
        try {
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer, BigInteger.valueOf(SERIAL.incrementAndGet()),
                    Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(365))),
                    subject, subjectKeys.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
            builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectKeys.getPublic()));
            if (crlDistributionPoint != null) {
                GeneralNames names = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlDistributionPoint.toString()));
                builder.addExtension(Extension.cRLDistributionPoints, false,
                        new CRLDistPoint(new DistributionPoint[] { new DistributionPoint(new DistributionPointName(names), null, null) }));
            }
            extraExtensions.accept(builder);
            return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
