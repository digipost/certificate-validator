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
package no.digipost.function;

import org.junit.Test;

import java.util.Optional;

import static no.digipost.function.Functions.autoClosing;
import static org.junit.Assert.fail;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;

public class FunctionsTest {

	@Test
	public void autoClosingSuccessfulFunction() throws Exception {
		AutoCloseable resource = Optional.of(mock(AutoCloseable.class)).map(autoClosing(r -> r)).get();
		then(resource).should(times(1)).close();
	}

	@Test
	public void autoClosingWhenExceptionIsThrownFromFunction() throws Exception {
		Optional<AutoCloseable> resource = Optional.of(mock(AutoCloseable.class));
		try {
			resource.map(autoClosing(r -> {throw new Exception();}));
		} catch (Exception e) {
			then(resource.get()).should(times(1)).close();
			return;
		}
		fail("Should have thrown exception");
	}

}
