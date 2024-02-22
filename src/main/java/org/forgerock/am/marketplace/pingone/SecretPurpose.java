/*
 * Copyright 2023 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.am.marketplace.pingone;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.forgerock.openam.annotations.EvolvingAll;
import org.forgerock.openam.sm.annotations.adapters.TypeAdapterClass;

/**
 * Type adapter annotation for giving information about a secret purpose.
 */
@EvolvingAll
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@TypeAdapterClass(SecretPurposeTypeAdapter.class)
public @interface SecretPurpose {
    /**
     * The secret label value. It should contain exactly one %s which is where the secret label identifier
     * will be inserted into the secret label.
     *
     * @return the secret label value.
     */
    String value();
}