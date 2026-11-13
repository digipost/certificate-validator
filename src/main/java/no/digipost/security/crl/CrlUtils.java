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

import java.net.URI;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static java.util.Collections.emptyList;
import static no.digipost.security.DigipostSecurity.describe;

public final class CrlUtils {

    private static final Logger LOG = LoggerFactory.getLogger(CrlUtils.class);


    /**
     * Find the HTTP(S) URIs of the CRL distribution points of a certificate.
     *
     * @param certificate the certificate
     * @return the URIs, or an empty list if the certificate has no HTTP(S) CRL distribution points
     */
    public static List<URI> findCrlDistributionPoints(X509Certificate certificate) {
        byte[] extensionValue = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (extensionValue == null) {
            return emptyList();
        }
        try {
            CRLDistPoint distPoint = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extensionValue));
            List<URI> uris = new ArrayList<>();
            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                DistributionPointName name = dp.getDistributionPoint();
                if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
                    continue;
                }
                for (GeneralName generalName : GeneralNames.getInstance(name.getName()).getNames()) {
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
            }
            return uris;
        } catch (Exception e) {
            LOG.warn("Error extracting CRL distribution points from {}: {} '{}'", describe(certificate), e.getClass().getSimpleName(), e.getMessage(), e);
            return emptyList();
        }
    }


    /**
     * Determine if a CRL can be used for deciding revocation status of a certificate issued by
     * {@code issuer}. The CRL must be issued and signed by {@code issuer}, be current at the given time,
     * and must not be a delta CRL, an indirect CRL, or a partitioned CRL which covers only some
     * certificates or revocation reasons.
     *
     * @param crl the CRL
     * @param issuer the expected issuer of the CRL
     * @param now the current time
     * @return {@code true} if the CRL is usable, {@code false} otherwise
     */
    public static boolean isUsableCrlFor(X509CRL crl, X509Certificate issuer, Instant now) {
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
                if (idp.onlyContainsUserCerts() || idp.onlyContainsAttributeCerts() || idp.getOnlySomeReasons() != null || idp.isIndirectCRL()) {
                    LOG.warn("CRL from {} is partitioned or indirect ({}), which is not supported", describe(issuer), idp);
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


    private CrlUtils() {}
}
