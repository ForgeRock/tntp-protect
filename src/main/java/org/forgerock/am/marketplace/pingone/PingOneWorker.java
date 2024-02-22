/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
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

import org.forgerock.openam.sm.annotations.adapters.TypeAdapterClass;

/**
 * Indicates that the annotated method declares an attribute that holds the ID of a
 * {@link org.forgerock.openam.integration.pingone.PingOneWorkerConfig.Worker}.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@TypeAdapterClass(PingOneWorkerTypeAdapter.class)
public @interface PingOneWorker {
}