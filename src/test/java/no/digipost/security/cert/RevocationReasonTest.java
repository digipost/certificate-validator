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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.quicktheories.generators.SourceDSL;

import java.util.Set;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toSet;
import static no.digipost.security.cert.RevocationReason.UNKNOWN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.quicktheories.QuickTheory.qt;
import static org.quicktheories.generators.SourceDSL.integers;

public class RevocationReasonTest {

    @Test
    public void managesToResolveAnyReason() {
        qt()
            .forAll(integers().all())
            .as(RevocationReason::resolve)
            .checkAssert(Assertions::assertNotNull);
    }

    @Test
    public void resolveParticularReason() {
        qt()
            .forAll(SourceDSL.arbitrary().enumValues(RevocationReason.class))
            .asWithPrecursor(reason -> RevocationReason.resolve(reason.code))
            .checkAssert(Assertions::assertSame);
    }

    @Test
    public void unknownReasonCodes() {
        Set<Integer> knownReasons = Stream.of(RevocationReason.values()).filter(r -> r != UNKNOWN).map(r -> r.code).collect(toSet());
        qt()
            .forAll(integers().all())
            .assuming(code -> !knownReasons.contains(code))
            .as(RevocationReason::resolve)
            .checkAssert(reason -> assertThat(reason, is(UNKNOWN)));
    }


}
