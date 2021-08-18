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

import java.time.Clock;

import static no.digipost.security.cert.ProdEnvCertificates.buypassClass3Ca3;
import static no.digipost.security.cert.ProdEnvCertificates.buypassClass3RootCa;
import static no.digipost.security.cert.ProdEnvCertificates.commfidesCa;
import static no.digipost.security.cert.ProdEnvCertificates.commfidesRootCa;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3Test4Ca3;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3Test4RootCa;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3TestCaG2Psd2QWAC;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3TestCaG2SoftToken;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3TestRootCaG2Psd2QWAC;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3TestRootCaG2SoftToken;
import static no.digipost.security.cert.TestEnvCertificates.commfidesTestCa;
import static no.digipost.security.cert.TestEnvCertificates.commfidesTestRootCa;

public final class TrustFactory {

    private final Clock clock;

    public TrustFactory(Clock clock) {
        this.clock = clock;
    }

    public Trust buypassAndCommfidesEnterpriseCertificates() {
        return Trust.merge(buypassEnterpriseCertificates(), commfidesEnterpriseCertificates());
    }

    public Trust buypassAndCommfidesTestEnterpriseCertificates() {
        return Trust.merge(buypassTestEnterpriseCertificates(), commfidesTestEnterpriseCertificates());
    }

    public Trust buypassEnterpriseCertificates() {
        return Trust.from(clock, buypassClass3RootCa(), buypassClass3Ca3());
    }

    public Trust buypassTestEnterpriseCertificates() {
        return Trust.from(clock, buypassClass3Test4RootCa(), buypassClass3Test4Ca3());
    }

    public Trust buypassSeid2TestEnterpriseCertificates() {
        return Trust.from(clock,
                buypassClass3TestRootCaG2Psd2QWAC(), buypassClass3TestCaG2Psd2QWAC(),
                buypassClass3TestRootCaG2SoftToken(), buypassClass3TestCaG2SoftToken());
    }

    public Trust commfidesEnterpriseCertificates() {
        return Trust.from(clock, commfidesRootCa(), commfidesCa());
    }

    public Trust commfidesTestEnterpriseCertificates() {
        return Trust.from(clock, commfidesTestRootCa(), commfidesTestCa());
    }

}
