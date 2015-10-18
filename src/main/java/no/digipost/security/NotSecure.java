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
package no.digipost.security;

/**
 * Thrown when a non-secure resource (e.g. connection, http request, etc) has
 * been encountered where a secured is expected.
 */
public class NotSecure extends RuntimeException {

    public NotSecure(Class<?> resourceType, Object instance) {
        this(resourceType.getSimpleName() + " (" + instance + ")");
    }

    public NotSecure(String resourceType) {
        this(resourceType, null);
    }

    public NotSecure(String resourceType, Throwable cause) {
        super("A secure " + resourceType + " was expected, but it was not.", cause);
    }

}
