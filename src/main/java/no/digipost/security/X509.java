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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.util.regex.Pattern.CASE_INSENSITIVE;

public final class X509 {

    private static final Logger LOG = LoggerFactory.getLogger(X509.class);

    /**
     * Used by some obscure cases to embed Norwegian "organisasjonsnummer" in certificates.
     */
    private static final Pattern CN_PATTERN = Pattern.compile("CN=([0-9]{9})([^0-9].*)?$");

    /**
     * Most common way to embed Norwegian "organisasjonsnummer" in certificates.
     */
    private static final Pattern SERIALNUMBER_PATTERN = Pattern.compile("SERIALNUMBER=([0-9]{9})", CASE_INSENSITIVE);


    /**
     * Try to find Norwegian "organisasjonsnummer" in an {@link X509Certificate}.
     */
    public static final Optional<String> findOrganisasjonsnummer(X509Certificate certificate) {
        String subjectDnName = certificate.getSubjectDN().getName();
        return find(certificate,
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


    private static final Optional<String> tryFindOrgnr(CharSequence text, Pattern extractPattern) {
        Optional<String> extracted = Optional.of(text).map(extractPattern::matcher).filter(Matcher::find).map(m -> m.group(1));
        if (!extracted.isPresent()) {
            LOG.trace("Orgnr ikke funnet i '{}' v.h.a. regex '{}'", text, extractPattern);
        }
        return extracted;
    }

    private X509() {}
}
