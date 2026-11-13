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
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static java.util.Arrays.asList;
import static no.digipost.security.crl.CrlUtils.findCrlDistributionPoints;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

class CrlUtilsTest {

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
