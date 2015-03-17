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

import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

public final class Functions {

	public static final Function<Exception, String> exceptionNameAndMessage = e -> e.getClass().getSimpleName() + ": " + e.getMessage();

	public static final Function<Exception, RuntimeException> asUnchecked = asUnchecked(exceptionNameAndMessage);

	public static final Function<Exception, RuntimeException> asUnchecked(Function<Exception, String> message) {
		return e ->	e instanceof RuntimeException ? (RuntimeException) e : new RuntimeException(message.apply(e), e);
	}

	public static final Consumer<Exception> rethrowAnyException = rethrow(asUnchecked);

	public static final <T extends Throwable> Consumer<T> rethrow(Function<T, RuntimeException> createUnchecked) { return e -> {throw createUnchecked.apply(e);}; }

	public static <T, R> Function<T, Optional<R>> mayThrowException(CheckedExceptionFunction<T, R, ? extends Exception> function, Consumer<Exception> exceptionHandler) {
		return mayThrowException(function, (t, e) -> exceptionHandler.accept(e));
	}

	public static <T, R> Function<T, Optional<R>> mayThrowException(CheckedExceptionFunction<T, R, ? extends Exception> function, BiConsumer<? super T, Exception> exceptionHandler) {
		return t -> {
			try {
				return Optional.of(function.apply(t));
			} catch (Exception e) {
				exceptionHandler.accept(t, e);
				return Optional.empty();
			}
		};
	}

	private Functions() {}

}
