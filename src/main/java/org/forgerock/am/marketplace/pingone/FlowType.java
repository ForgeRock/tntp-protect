/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.am.marketplace.pingone;


/**
 * PingOne protect evaluation Flow Type.
 */
public enum FlowType {

    /**
     * Registration.
     */
    REGISTRATION,
    /**
     * Authentication.
     */
    AUTHENTICATION,
    /**
     * Access.
     */
    ACCESS,
    /**
     * Authorization.
     */
    AUTHORIZATION,
    /**
     * Transaction.
     */
    TRANSACTION;

}