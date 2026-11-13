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
package no.digipost.security.crl;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static java.util.Arrays.asList;
import static no.digipost.security.crl.CrlUtils.findCrlDistributionPoints;
import static no.digipost.security.crl.CrlUtils.isUsableCrlFor;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;

class CrlUtilsTest {

    private static final Instant NOW = Instant.now();
    private static final X500Name ISSUER_NAME = new X500Name("CN=Test Issuer, O=Test");
    private static final String USER_CRL = "http://crl.example.test/user.crl";
    private static final String CA_CRL = "http://crl.example.test/ca.crl";
    private static final KeyPair ISSUER_KEYS = generateKeyPair();
    private static final X509Certificate ISSUER = certificate(ISSUER_NAME, ISSUER_KEYS, true);
    private static final X509Certificate ISSUED_USER = certificate(new X500Name("CN=Test User, O=Test"), generateKeyPair(), false, USER_CRL);
    private static final X509Certificate ISSUED_CA = certificate(new X500Name("CN=Test CA, O=Test"), generateKeyPair(), true, CA_CRL);


    @Test
    void malformedDistributionPointDoesNotDiscardValidHttpDistributionPoints() throws Exception {
        X509Certificate certificate = certificateWithCrlDistributionPoints(
                "http://crl.example.test/first.crl",
                "ldap://dir.example.test/cn=CA 1,o=X?certificateRevocationList",
                "http://crl.example.test/malformed path.crl",
                "HTTPS://crl.example.test/second.crl");

        assertThat(findCrlDistributionPoints(certificate), contains(
                URI.create("http://crl.example.test/first.crl"),
                URI.create("HTTPS://crl.example.test/second.crl")));
    }

    @Test
    void crlOnlyContainingCaCertificatesIsOnlyUsableForCaCertificates() throws Exception {
        X509CRL crl = crlWithIssuingDistributionPoint(new IssuingDistributionPoint(null, false, true, null, false, false));

        assertThat(isUsableCrlFor(crl, ISSUED_CA, ISSUER, NOW), is(true));
        assertThat(isUsableCrlFor(crl, ISSUED_USER, ISSUER, NOW), is(false));
    }

    @Test
    void crlOnlyContainingUserCertificatesIsOnlyUsableForNonCaCertificates() throws Exception {
        X509CRL crl = crlWithIssuingDistributionPoint(new IssuingDistributionPoint(null, true, false, null, false, false));

        assertThat(isUsableCrlFor(crl, ISSUED_USER, ISSUER, NOW), is(true));
        assertThat(isUsableCrlFor(crl, ISSUED_CA, ISSUER, NOW), is(false));
    }

    @Test
    void crlWithDistributionPointIsOnlyUsableForCertificatesWithTheSameDistributionPoint() throws Exception {
        X509CRL crl = crlWithIssuingDistributionPoint(new IssuingDistributionPoint(distributionPointName(USER_CRL), false, false, null, false, false));

        assertThat(isUsableCrlFor(crl, ISSUED_USER, ISSUER, NOW), is(true));
        assertThat(isUsableCrlFor(crl, ISSUED_CA, ISSUER, NOW), is(false));
        assertThat(isUsableCrlFor(crl, certificate(new X500Name("CN=Test User Without CRL Distribution Point, O=Test"), generateKeyPair(), false), ISSUER, NOW), is(false));
    }

    @Test
    void crlWithoutIssuingDistributionPointIsUsableForAllCertificates() throws Exception {
        X509CRL crl = crlWithIssuingDistributionPoint(null);

        assertThat(isUsableCrlFor(crl, ISSUED_USER, ISSUER, NOW), is(true));
        assertThat(isUsableCrlFor(crl, ISSUED_CA, ISSUER, NOW), is(true));
    }


    private static X509CRL crlWithIssuingDistributionPoint(IssuingDistributionPoint idp) throws Exception {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(ISSUER_NAME, Date.from(NOW.minus(Duration.ofHours(1))));
        builder.setNextUpdate(Date.from(NOW.plus(Duration.ofDays(1))));
        if (idp != null) {
            builder.addExtension(Extension.issuingDistributionPoint, true, idp);
        }
        return new JcaX509CRLConverter().getCRL(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(ISSUER_KEYS.getPrivate())));
    }

    /**
     * A certificate issued by {@link #ISSUER}.
     */
    private static X509Certificate certificate(X500Name subject, KeyPair subjectKeys, boolean ca, String ... crlDistributionPoints) {
        try {
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(ISSUER_NAME, BigInteger.ONE,
                    Date.from(NOW.minus(Duration.ofDays(1))), Date.from(NOW.plus(Duration.ofDays(1))), subject, subjectKeys.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
            if (crlDistributionPoints.length > 0) {
                builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(asList(crlDistributionPoints).stream()
                        .map(uri -> new DistributionPoint(distributionPointName(uri), null, null))
                        .toArray(DistributionPoint[]::new)));
            }
            return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(ISSUER_KEYS.getPrivate())));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static DistributionPointName distributionPointName(String uri) {
        return new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, uri)));
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

    private static X509Certificate certificateWithCrlDistributionPoints(String ... uris) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        X500Name name = new X500Name("CN=Test, O=Test");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(1))), name, keys.getPublic());
        builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(asList(uris).stream()
                .map(uri -> new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, uri))), null, null))
                .toArray(DistributionPoint[]::new)));
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())));
    }
}
