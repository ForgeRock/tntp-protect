/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.am.marketplace.pingone;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;
import java.util.Optional;

import javax.inject.Named;

import org.forgerock.http.Handler;
import org.forgerock.http.header.AuthorizationHeader;
import org.forgerock.http.header.MalformedHeaderException;
import org.forgerock.http.header.authorization.BasicCredentials;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.http.HttpConstants;
import org.forgerock.openam.oauth2.token.stateless.StatelessAccessToken;
import org.forgerock.openam.secrets.Secrets;
import org.forgerock.openam.sm.annotations.subconfigs.Multiple;
import org.forgerock.services.context.RootContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.iplanet.sso.SSOException;
import com.sun.identity.sm.SMSException;

/**
 * PingOne Worker Service, as a client to PingOne Worker client and manage AccessToken.
 */
@Singleton
public class PingOneWorkerService {

    private static final Logger logger = LoggerFactory.getLogger(PingOneWorkerService.class);
    private final PingOneWorkerConfig config;

    private final Handler handler;
    private final Secrets secrets;
    private final LoadingCache<WorkerKey, AccessToken> accessTokenCache;

    /**
     * Create the Service using Guice injection. Just-in-time bindings can be used to obtain instances of
     * other classes from the plugin.
     *
     * @param config The {@link PingOneWorkerConfig} configuration
     * @param handler Network handler
     * @param secrets The Secrets API
     */
    @Inject
    public PingOneWorkerService(
        PingOneWorkerConfig config,
        @Named("CloseableHttpClientHandler") Handler handler,
        Secrets secrets) {
        this.config = config;
        this.handler = handler;
        this.secrets = secrets;
        this.accessTokenCache = CacheBuilder.newBuilder()
            .build(new CacheLoader<>() {
                @Override
                public AccessToken load(WorkerKey key) throws Exception {
                    return getToken(key.realm, key.worker);
                }
            });
        config.watch().onRealmChange(realm -> accessTokenCache.invalidateAll()).listen();
    }

    /**
     * Retrieve the Worker configurations.
     *
     * @param realm The Realm
     * @return The Worker configurations.
     */
    public Multiple<PingOneWorkerConfig.Worker> getWorkers(Realm realm) {
        PingOneWorkerConfig.Realm realmConfig = config.realmSingleton(realm)
            .orElse(config.realmDefaults());
        return realmConfig.workers();
    }

    /**
     * Retrieve the Worker configuration.
     *
     * @param realm The Realm
     * @param configName The configuration name
     * @return The Worker configuration.
     */
    public Optional<PingOneWorkerConfig.Worker> getWorker(Realm realm, String configName) {
        PingOneWorkerConfig.Realm realmConfig = config.realmSingleton(realm)
            .orElse(config.realmDefaults());

        if (!realmConfig.enabled()) {
            logger.warn("PingOne Worker config is disabled: {}", configName);
            return Optional.empty();
        }

        PingOneWorkerConfig.Worker worker;
        try {
            worker = realmConfig.workers().get(configName);
            if (worker == null) {
                logger.error("PingOne Worker not found: {}", configName);
                return Optional.empty();
            }
            return Optional.of(worker);
        } catch (SMSException | SSOException e) {
            logger.error("PingOne Worker not found: {}", configName, e);
            return Optional.empty();
        }
    }

    /**
     * Get Access Token.
     *
     * @param realm The realm.
     * @param worker PingOne Worker Client Service
     * @return The PingOne Worker AccessToken
     */
    public AccessToken getAccessToken(Realm realm, PingOneWorkerConfig.Worker worker) throws PingOneWorkerException {

        try {
            WorkerKey key = new WorkerKey(realm, worker);
            AccessToken token = accessTokenCache.get(key);
            if (!token.isExpired()) {
                return token;
            } else {
                accessTokenCache.invalidate(key);
            }
            return accessTokenCache.get(key);

        } catch (Exception e) {
            throw new PingOneWorkerException(
                "Failed to retrieve PingOne Worker access token", e);
        }
    }

    private AccessToken getToken(Realm realm, PingOneWorkerConfig.Worker worker)
            throws MalformedHeaderException, IOException, InterruptedException, PingOneWorkerException {

        URI uri = URI.create(worker.authUrl() + "/" + worker.environmentId() + "/as/token");
        Request request = new Request().setUri(uri).setMethod(HttpConstants.Methods.POST);
        Form form = new Form();
        form.putSingle("grant_type", "client_credentials");
        form.putSingle("scope", "openid");
        request.getEntity().setForm(form);
        AuthorizationHeader header = new AuthorizationHeader();
        BasicCredentials basicCredentials = new BasicCredentials(worker.clientId(),
            getClientSecret(realm, worker));
        header.setRawValue("Basic " + basicCredentials);
        request.addHeaders(header);
        Response response = handler.handle(new RootContext(), request).getOrThrow();
        if (response.getStatus() == Status.OK) {
            JsonValue resp = JsonValue.json(response.getEntity().getJson());
            String accessToken = resp.get("access_token").asString();
            Jwt jwt = new JwtReconstruction().reconstructJwt(accessToken, Jwt.class);
            return new StatelessAccessToken(jwt, accessToken, worker.clientId());

        } else {
            throw new PingOneWorkerException("Failed to retrieve Worker Access Token."
                + response.getStatus()
                + "-" + response.getEntity().getString());
        }
    }

    private String getClientSecret(Realm realm, PingOneWorkerConfig.Worker worker) throws PingOneWorkerException {
        var validSecrets =
            secrets.getRealmSecrets(realm)
                .getValidSecrets(worker.clientSecretPurpose())
                .getOrThrowIfInterrupted()
                .map(s -> s.revealAsUtf8AndDestroy(String::new))
                .findFirst();

        if (validSecrets.isEmpty()) {
            throw new PingOneWorkerException("No valid keys found for client secret label: "
                 + worker.clientSecretPurpose().getLabel());
        }
        return validSecrets.get();
    }


    /**
     * The Worker Key, if the clientId and environmentId are equals, we consider the key are equal.
     */
    private static class WorkerKey {

        private final PingOneWorkerConfig.Worker worker;
        private final Realm realm;

        WorkerKey(Realm realm, PingOneWorkerConfig.Worker worker) {
            this.realm = realm;
            this.worker = worker;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            WorkerKey other = (WorkerKey) o;
            return Objects.equals(worker.clientId(), other.worker.clientId())
                && Objects.equals(worker.environmentId(), other.worker.environmentId());
        }

        @Override
        public int hashCode() {
            return Objects.hash(worker.clientId(), worker.environmentId());
        }
    }

}
