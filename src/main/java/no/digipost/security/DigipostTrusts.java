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

import no.digipost.security.cert.Trust;

import java.time.Clock;

import static no.digipost.security.cert.Certificates.buypassClass3Ca3;
import static no.digipost.security.cert.Certificates.buypassClass3RootCa;
import static no.digipost.security.cert.Certificates.commfidesCa;
import static no.digipost.security.cert.Certificates.commfidesRootCa;

public final class DigipostTrusts {

    private final Clock clock;

    public DigipostTrusts(Clock clock) {
        this.clock = clock;
    }

    public Trust buypassAndCommfidesEnterpriseCertificates() {
        return Trust.merge(buypassEnterpriseCertificates(), commfidesEnterpriseCertificates());
    }

    public Trust buypassEnterpriseCertificates() {
        return Trust.from(clock, buypassClass3RootCa(), buypassClass3Ca3());
    }

    public Trust commfidesEnterpriseCertificates() {
        return Trust.from(clock, commfidesRootCa(), commfidesCa());
    }


}
