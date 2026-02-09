/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package android.annotation;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.RetentionPolicy.SOURCE;

@Retention(SOURCE)
@Target({ANNOTATION_TYPE})
public @interface IntDef {
    /**
     * Defines the constant prefix for this element
     */
    String[] prefix() default {};

    /**
     * Defines the constant suffix for this element
     */
    String[] suffix() default {};

    /**
     * Defines the allowed constants for this element
     */
    int[] value() default {};

    /**
     * Defines whether the constants can be used as a flag, or just as an enum (the default)
     */
    boolean flag() default false;
}