/**
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

import com.pholser.junit.quickcheck.Property;
import com.pholser.junit.quickcheck.runner.JUnitQuickcheck;
import org.junit.runner.RunWith;

import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;
import static no.digipost.security.cert.RevocationReason.UNKNOWN;
import static org.hamcrest.Matchers.in;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeThat;

@RunWith(JUnitQuickcheck.class)
public class RevocationReasonTest {

    @Property
    public void managesToResolveAnyReason(int code) {
        assertThat(RevocationReason.resolve(code), notNullValue());
    }

    @Property
    public void resolveParticularReason(RevocationReason reason) {
        assertThat(RevocationReason.resolve(reason.code), sameInstance(reason));
    }

    @Property
    public void unknownReasonCodes(int unknownCode) {
        assumeThat(unknownCode, not(in(Stream.of(RevocationReason.values()).filter(r -> r != UNKNOWN).map(r -> r.code).collect(toList()))));
        assertThat(RevocationReason.resolve(unknownCode), is(UNKNOWN));
    }


}
