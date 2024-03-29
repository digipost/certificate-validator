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
package no.digipost.security;

import no.digipost.security.cert.BasicConstraints;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static javax.security.auth.x500.X500Principal.RFC1779;

public final class X509 {

    private static final Logger LOG = LoggerFactory.getLogger(X509.class);

    /**
     * Used by some obscure cases to embed Norwegian "organisasjonsnummer" in certificates.
     */
    private static final Pattern CN_PATTERN = Pattern.compile("CN=([0-9]{9})([^0-9].*)?$");

    /**
     * Most common way to embed Norwegian "organisasjonsnummer" in certificates.
     *
     * @see <a href="http://www.oid-info.com/get/2.5.4.5">OID 2.5.4.5</a>
     */
    private static final Pattern SERIALNUMBER_PATTERN = Pattern.compile("OID\\.2\\.5\\.4\\.5=([0-9]{9})", CASE_INSENSITIVE);

    /**
     * SEID 2 way to embed Norwegian "organisasjonsnummer" in certificates.
     *
     * @see <a href="http://www.oid-info.com/get/2.5.4.97">OID 2.5.4.97</a>
     */
    private static final Pattern SEID2_PATTERN = Pattern.compile("OID\\.2\\.5\\.4\\.97=(?:NTRNO-)?([0-9]{9})", CASE_INSENSITIVE);


    /**
     * Try to find Norwegian "organisasjonsnummer" in an {@link X509Certificate}.
     */
    public static final Optional<String> findOrganisasjonsnummer(X509Certificate certificate) {
        String subjectDnName = certificate.getSubjectX500Principal().getName(RFC1779);
        return find(certificate,
                    cert -> tryFindOrgnr(subjectDnName, SEID2_PATTERN),
                    cert -> tryFindOrgnr(subjectDnName, SERIALNUMBER_PATTERN),
                    cert -> tryFindOrgnr(subjectDnName, CN_PATTERN))
                .findFirst();
    }


    /**
     * Try to find (or derive) data in an {@link X509Certificate}.
     */
    @SafeVarargs
    public static final <R> Stream<R> find(X509Certificate certificate, Function<? super X509Certificate, ? extends Optional<R>> ... extractors) {
        return Stream.of(extractors).map(f -> f.apply(certificate)).filter(Optional::isPresent).map(Optional::get);
    }


    /**
     * Extract the basic constraints extension value of a certificate, which
     * can be used to determine if certificate is a CA or not.
     *
     * @return the resolved {@link BasicConstraints}
     */
    public static final BasicConstraints getBasicConstraints(X509Certificate certificate) {
        return BasicConstraints.from(certificate);
    }


    private static final Optional<String> tryFindOrgnr(CharSequence text, Pattern extractPattern) {
        Optional<String> extracted = Optional.of(text).map(extractPattern::matcher).filter(Matcher::find).map(m -> m.group(1));
        if (!extracted.isPresent() && LOG.isTraceEnabled()) {
            LOG.trace("Orgnr ikke funnet i '{}' v.h.a. regex '{}'", text, extractPattern);
        }
        return extracted;
    }

    private X509() {}
}
