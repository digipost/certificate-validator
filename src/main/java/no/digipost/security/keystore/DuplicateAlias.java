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
package no.digipost.security.keystore;

import no.digipost.security.DigipostSecurity;

import java.security.cert.Certificate;
import java.util.List;

import static java.util.Arrays.asList;
import static java.util.stream.Collectors.joining;

public class DuplicateAlias extends RuntimeException {

    public DuplicateAlias(String alias, Certificate firstCertificate, Certificate secondCertificate) {
        this(alias, asList(firstCertificate, secondCertificate), null);
    }

    public DuplicateAlias(String alias, List<? extends Certificate> certificates, Throwable cause) {
        super("Duplicate alias '" + alias + "' detected for certificates: " + certificates.stream().map(DigipostSecurity::describe).collect(joining(", ")), cause);
    }
}
