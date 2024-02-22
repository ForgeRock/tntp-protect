/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.am.marketplace.pingone;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.io.IOException;
import java.net.URI;

import javax.inject.Named;

import org.forgerock.http.Handler;
import org.forgerock.http.header.AuthorizationHeader;
import org.forgerock.http.header.MalformedHeaderException;
import org.forgerock.http.header.authorization.BearerToken;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.openam.http.HttpConstants;
import org.forgerock.services.context.RootContext;

import com.google.inject.Inject;
import com.google.inject.Singleton;

/**
 * Service to integrate with PingOne Protect APIs.
 */
@Singleton
public class PingOneProtectService {
    private final Handler handler;

    /**
     * Constructor of the PingOneProtectService.
     *
     * @param handler Handler to handle http request
     */
    @Inject
    public PingOneProtectService(
            @Named("CloseableHttpClientHandler") Handler handler) {
        this.handler = handler;
    }

    /**
     * the POST /environments/{{envID}}/riskEvaluations operation to create a new risk evaluation
     * resource associated with the environment specified in the request URL.
     * The request body defines the event that is processed for risk evaluation.
     *
     * @param accessToken The {@link AccessToken} from {@link PingOneProtectService}
     * @param worker The worker {@link PingOneWorkerConfig}
     * @param body The request body
     * @return The response from /environments/{{envID}}/riskEvaluations operation
     * @throws PingOneWorkerException When API response != 201
     */
    public JsonValue evaluate(AccessToken accessToken, PingOneWorkerConfig.Worker worker, JsonValue body)
            throws PingOneWorkerException {
        try {
            URI uri = URI.create(worker.apiUrl() + "/environments/" + worker.environmentId() + "/riskEvaluations");
            Request request = new Request().setUri(uri).setMethod(HttpConstants.Methods.POST);
            request.getEntity().setJson(body);
            addAuthorizationHeader(request, accessToken);
            Response response = handler.handle(new RootContext(), request).getOrThrow();
            if (response.getStatus() == Status.CREATED) {
                return json(response.getEntity().getJson());
            } else {
                throw new PingOneWorkerException("PingOne Create Risk Evaluation API response with error."
                        + response.getStatus()
                        + "-" + response.getEntity().getString());
            }
        } catch (MalformedHeaderException | InterruptedException | IOException e) {
            throw new PingOneWorkerException("Failed to create risk evaluation", e);
        }
    }

    /**
     * Use PUT /environments/{{envID}}/riskEvaluations/{{riskID}}/event to update the risk evaluation configuration,
     * and to modify the completion status of the resource when the risk evaluation is still in progress.
     *
     * @param accessToken The {@link AccessToken} from {@link PingOneProtectService}
     * @param worker The worker {@link PingOneWorkerConfig}
     * @param riskEvalId The risk evaluation id
     * @param status The completion status
     * @return The response from /environments/{{envID}}/riskEvaluations operation
     * @throws PingOneWorkerException When API response != 200
     */
    public JsonValue event(AccessToken accessToken, PingOneWorkerConfig.Worker worker, String riskEvalId, String status)
            throws PingOneWorkerException {
        try {
            URI uri = URI.create(worker.apiUrl() + "/environments/" + worker.environmentId() + "/riskEvaluations/"
                    + riskEvalId + "/event");
            Request request = new Request().setUri(uri).setMethod(HttpConstants.Methods.PUT);
            request.getEntity().setJson(object(field("completionStatus", status)));
            addAuthorizationHeader(request, accessToken);
            Response response = handler.handle(new RootContext(), request).getOrThrow();
            if (response.getStatus() == Status.OK) {
                return json(response.getEntity().getJson());
            } else {
                throw new PingOneWorkerException("PingOne Update Risk Evaluation API response with error."
                        + response.getStatus()
                        + "-" + response.getEntity().getString());
            }
        } catch (MalformedHeaderException | InterruptedException | IOException e) {
            throw new PingOneWorkerException("Failed to update risk evaluation", e);
        }
    }

    private void addAuthorizationHeader(Request request, AccessToken accessToken) throws MalformedHeaderException {
        AuthorizationHeader header = new AuthorizationHeader();
        BearerToken bearerToken = new BearerToken(accessToken.getTokenId());
        header.setRawValue(BearerToken.NAME + " " + bearerToken);
        request.addHeaders(header);
    }
}
