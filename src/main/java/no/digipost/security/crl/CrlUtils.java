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

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static no.digipost.security.DigipostSecurity.describe;

public final class CrlUtils {

    private static final Logger LOG = LoggerFactory.getLogger(CrlUtils.class);


    /**
     * @param certificate the certificate
     * @return the HTTP(S) URIs of the certificate's CRL distribution points, possibly empty
     */
    public static List<URI> findCrlDistributionPoints(X509Certificate certificate) {
        byte[] extensionValue = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (extensionValue == null) {
            return emptyList();
        }
        try {
            List<URI> uris = new ArrayList<>();
            for (GeneralName generalName : crlDistributionPointNames(extensionValue)) {
                if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    String value = ASN1IA5String.getInstance(generalName.getName()).getString();
                    if (!value.regionMatches(true, 0, "http:", 0, 5) && !value.regionMatches(true, 0, "https:", 0, 6)) {
                        continue;
                    }
                    try {
                        uris.add(URI.create(value));
                    } catch (IllegalArgumentException e) {
                        LOG.warn("Ignoring malformed CRL distribution point '{}' in {}: {}", value, describe(certificate), e.getMessage());
                    }
                }
            }
            return uris;
        } catch (Exception e) {
            LOG.warn("Error extracting CRL distribution points from {}: {} '{}'", describe(certificate), e.getClass().getSimpleName(), e.getMessage(), e);
            return emptyList();
        }
    }

    /**
     * @return the full names of all the distribution points in a CRL distribution points extension
     */
    private static List<GeneralName> crlDistributionPointNames(byte[] extensionValue) throws IOException {
        CRLDistPoint distPoint = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extensionValue));
        List<GeneralName> names = new ArrayList<>();
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName name = dp.getDistributionPoint();
            if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
                names.addAll(asList(GeneralNames.getInstance(name.getName()).getNames()));
            }
        }
        return names;
    }


    /**
     * Determine if a CRL is issued and signed by {@code issuer}, is current, is complete,
     * i.e. not a delta, indirect or partitioned by reasons, and that its scope covers {@code certificate}.
     *
     * @param crl the CRL
     * @param certificate the certificate to check with the CRL
     * @param issuer the expected issuer of the CRL
     * @param now the current time
     * @return {@code true} if the CRL is usable
     */
    public static boolean isUsableCrlFor(X509CRL crl, X509Certificate certificate, X509Certificate issuer, Instant now) {
        if (!crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            LOG.warn("CRL issued by {} is not issued by expected issuer {}", crl.getIssuerX500Principal(), describe(issuer));
            return false;
        }
        try {
            crl.verify(issuer.getPublicKey());
        } catch (Exception e) {
            LOG.warn("CRL from {} failed signature verification: {} '{}'", describe(issuer), e.getClass().getSimpleName(), e.getMessage());
            return false;
        }
        if (crl.getThisUpdate().toInstant().isAfter(now)) {
            LOG.warn("CRL from {} is not yet valid, thisUpdate is {}", describe(issuer), crl.getThisUpdate().toInstant());
            return false;
        }
        if (crl.getNextUpdate() == null || !crl.getNextUpdate().toInstant().isAfter(now)) {
            LOG.warn("CRL from {} is outdated, nextUpdate is {}", describe(issuer), crl.getNextUpdate() == null ? null : crl.getNextUpdate().toInstant());
            return false;
        }
        if (crl.getExtensionValue(Extension.deltaCRLIndicator.getId()) != null) {
            LOG.warn("CRL from {} is a delta CRL, which is not supported", describe(issuer));
            return false;
        }
        byte[] idpValue = crl.getExtensionValue(Extension.issuingDistributionPoint.getId());
        if (idpValue != null) {
            try {
                IssuingDistributionPoint idp = IssuingDistributionPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(idpValue));
                if (idp.onlyContainsAttributeCerts() || idp.getOnlySomeReasons() != null || idp.isIndirectCRL()) {
                    LOG.warn("CRL from {} is partitioned or indirect ({}), which is not supported", describe(issuer), idp);
                    return false;
                }
                boolean ca = certificate.getBasicConstraints() >= 0;
                if ((idp.onlyContainsCACerts() && !ca) || (idp.onlyContainsUserCerts() && ca)) {
                    LOG.warn("CRL from {} does not cover {}, scope is {}", describe(issuer), describe(certificate), idp);
                    return false;
                }
                if (idp.getDistributionPoint() != null && !isDistributionPointOf(idp.getDistributionPoint(), certificate)) {
                    LOG.warn("CRL from {} does not cover {}, distribution point {} is not in the certificate", describe(issuer), describe(certificate), idp.getDistributionPoint());
                    return false;
                }
            } catch (Exception e) {
                LOG.warn("Error reading issuing distribution point of CRL from {}: {} '{}'", describe(issuer), e.getClass().getSimpleName(), e.getMessage());
                return false;
            }
        }
        Set<String> criticalExtensions = crl.getCriticalExtensionOIDs();
        if (criticalExtensions != null) {
            for (String oid : criticalExtensions) {
                if (!oid.equals(Extension.issuingDistributionPoint.getId())) {
                    LOG.warn("CRL from {} has unsupported critical extension {}", describe(issuer), oid);
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * @return {@code true} if one of the names of a CRL's issuing distribution point is one of the
     *         CRL distribution points of the certificate
     */
    private static boolean isDistributionPointOf(DistributionPointName issuingDistributionPoint, X509Certificate certificate) throws IOException {
        byte[] extensionValue = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (extensionValue == null || issuingDistributionPoint.getType() != DistributionPointName.FULL_NAME) {
            return false;
        }
        List<GeneralName> certificateDistributionPoints = crlDistributionPointNames(extensionValue);
        return Stream.of(GeneralNames.getInstance(issuingDistributionPoint.getName()).getNames()).anyMatch(certificateDistributionPoints::contains);
    }


    private CrlUtils() {}
}
