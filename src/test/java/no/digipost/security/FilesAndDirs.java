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

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import static java.nio.file.Files.createDirectories;
import static java.nio.file.Files.exists;

public class FilesAndDirs {

    public static final Path basedir;

    static {
        try {
            basedir = Paths.get(FilesAndDirs.class.getResource("/").toURI()).getParent().getParent().normalize();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public static final Path target = basedir.resolve("target");

    /**
     * Prepare a new empty working directory in the {@link #target} directory.
     *
     * @see #newWorkDir(String)
     */
    public static Path newWorkDir() {
        return newWorkDir((String) null);
    }

    /**
     * Prepare a new empty working directory in the {@link #target} directory,
     * where the name contains the provided class' name.
     *
     * @see #newWorkDir(String)
     */
    public static Path newWorkDir(Class<?> cls) {
        return newWorkDir(cls.getSimpleName().toLowerCase());
    }


    /**
     * Prepare a new empty working directory in the {@link #target} directory.
     * The directory name will contain a timestamp and a random string to guarantie
     * it does not already exist. The directory will be created and be ready for use when
     * this method returns.
     *
     * @param name A name to include in the created directory. May be <code>null</code>.
     */
    public static Path newWorkDir(String name) {
        String randomString = UUID.randomUUID().toString();
        String timestamp = LocalDateTime.now().format(timestampFormat);
        Path newWorkingDir = target.resolve("work").resolve((name != null ? name + "_" : "") + timestamp + "_" + randomString);
        if (exists(newWorkingDir))
            throw new RuntimeException("Cannot create " + newWorkingDir + " because it already exists!");
        try {
            createDirectories(newWorkingDir);
        } catch (IOException e) {
            throw new RuntimeException("Cannot create " + newWorkingDir + ": " + e.getMessage(), e);
        }
        return newWorkingDir;
    }

    private static final DateTimeFormatter timestampFormat = DateTimeFormatter.ofPattern("yyyyMMdd.HHmmss.SSS");

}
