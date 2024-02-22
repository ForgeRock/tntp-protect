/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.am.marketplace.pingone;

/**
 * PingOne Worker Exception.
 */
public class PingOneWorkerException extends Exception {

    /**
     * Exception constructor with error message.
     *
     * @param message The error message.
     */
    public PingOneWorkerException(String message) {
        super(message);
    }

    /**
     * Exception constructor with error message and root cause.
     *
     * @param message The error message.
     * @param cause The root cause of error.
     */
    public PingOneWorkerException(String message, Throwable cause) {
        super(message, cause);
    }

}