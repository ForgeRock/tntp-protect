/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
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