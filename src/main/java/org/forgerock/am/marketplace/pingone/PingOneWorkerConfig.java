/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.am.marketplace.pingone;

import org.forgerock.am.config.RealmConfiguration;
import org.forgerock.am.config.ServiceComponentConfig;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.annotations.sm.Config;
import org.forgerock.openam.annotations.sm.Id;
import org.forgerock.openam.annotations.sm.SubConfig;
import org.forgerock.openam.shared.secrets.Labels;
import org.forgerock.openam.sm.annotations.subconfigs.Multiple;
import org.forgerock.secrets.GenericSecret;
import org.forgerock.secrets.Purpose;

/**
 * PingOne Worker Configuration.
 */
@Config(scope = Config.Scope.SERVICE, name = "PingOneWorkerService",
    i18nFile = "PingOneWorkerConfig",
    resourceName = "pingOneWorkerService")
public interface PingOneWorkerConfig extends ServiceComponentConfig,
    RealmConfiguration<PingOneWorkerConfig.Realm> {

    /**
     * The Realm.
     */
    @Config(scope = Config.Scope.REALM)
    interface Realm {

        /**
         * Whether this specific service config is enabled.
         *
         * @return true if it's enabled
         */
        @Attribute(order = 100, requiredValue = true)
        default boolean enabled() {
            return true;
        }

        /**
         * Container for the individual configurations.
         *
         * @return The worker configurations
         */
        @SubConfig(descriptionKey = "subConfig")
        Multiple<PingOneWorkerConfig.Worker> workers();
    }

    /**
     * Worker Configuration.
     */
    interface Worker {

        /**
         * The id of this node type.
         *
         * @return the id.
         */
        @Id
        String id();

        /**
         * The Client ID.
         *
         * @return The Client ID.
         */
        @Attribute(order = 100, requiredValue = true)
        default String clientId() {
            return "";
        }

        /**
         * The Client Secret label identifier.
         *
         * @return The Client Secret label identifier.
         */
        @Attribute(order = 200, requiredValue = true)
        @SecretPurpose(PingOneProtectEvaluationNode.REST_PINGONE_CLIENT_SECRET)
        Purpose<GenericSecret> clientSecretPurpose();

        /**
         * The Environment ID.
         *
         * @return The Environment ID.
         */
        @Attribute(order = 300, requiredValue = true)
        default String environmentId() {
            return "";
        }

        /**
         * PingOne API url.
         *
         * @return The PingOne API Url
         */
        @Attribute(order = 400, requiredValue = true)
        default String apiUrl() {
            return "https://api.pingone.com/v1";
        }

        /**
         * PingOne Auth url.
         *
         * @return The PingOne Auth Url
         */
        @Attribute(order = 500, requiredValue = true)
        default String authUrl() {
            return "https://auth.pingone.com";
        }

    }
}
