/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.marketplace.pingone;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang.text.StrSubstitutor;
import org.forgerock.http.HttpApplicationException;
import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.http.header.AuthorizationHeader;
import org.forgerock.http.header.MalformedHeaderException;
import org.forgerock.http.header.authorization.BearerToken;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.http.HttpConstants;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.thread.listener.ShutdownManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;




@Singleton
public class Helper {
	private final Logger logger = LoggerFactory.getLogger(Helper.class);
	private final String loggerPrefix = "[PingOne Verify Helper]" + PingOneProtectPlugin.logAppender;
	private final HttpClientHandler handler;
	
	@Inject
	public Helper(ShutdownManager shutdownManager) throws HttpApplicationException{
	    this.handler = new HttpClientHandler();
	    shutdownManager.addShutdownListener(() -> {
	      try {
	        handler.close();
	      } catch (IOException e) {
	        logger.error(loggerPrefix + " Could not close HTTP client", e);
	      }
	    });
	}
	
    protected static final String sdkJsPathTemplate = "org/forgerock/am/marketplace/pingone/client.js";
    protected static final String sdkJsPathSigTemplate = "org/forgerock/am/marketplace/pingone/getSigs.js";

	static protected ScriptTextOutputCallback getScriptedCallback(String clientScript, String environmentId, String consoleLogEnabled, String deviceAttributesToIgnore, String customHost, String lazyMetadata, String behavioralDataCollection, String deviceKeyRsyncIntervals, String enableTrust, String disableTags, String disableHub, String sdkURL) {
		Map<String, String> sdkConfigMap = new HashMap<>();
		sdkConfigMap.put("envId", environmentId);
		sdkConfigMap.put("consoleLogEnabled", consoleLogEnabled);
		sdkConfigMap.put("subrpcTarget", deviceAttributesToIgnore);
		sdkConfigMap.put("subchainId", customHost);
		sdkConfigMap.put("lazyMetadata", lazyMetadata);
		sdkConfigMap.put("behavioralDataCollection", behavioralDataCollection);
		sdkConfigMap.put("deviceKeyRsyncIntervals", deviceKeyRsyncIntervals);
		sdkConfigMap.put("enableTrust", enableTrust);
		sdkConfigMap.put("disableTags", disableTags);
		sdkConfigMap.put("disableHub", disableHub);
		sdkConfigMap.put("theUrl", sdkURL);
		String sdkJs = new StrSubstitutor(sdkConfigMap).replace(clientScript);
		ScriptTextOutputCallback callback = new ScriptTextOutputCallback(sdkJs);
		return callback;
	}
	
	static protected ScriptTextOutputCallback getSigCallback(String clientScript) {
		Map<String, String> sdkConfigMap = new HashMap<>();
		String sdkJs = new StrSubstitutor(sdkConfigMap).replace(clientScript);
		ScriptTextOutputCallback callback = new ScriptTextOutputCallback(sdkJs);
		return callback;
	}	
	

	static protected String readJS(String jsTemplate) throws NodeProcessException {
		URL resource = Resources.getResource(jsTemplate);
		try {
			return Resources.toString(resource, Charsets.UTF_8);
		} catch (IOException ex) {
			throw new NodeProcessException(ex);
		}
	}
	
	
	
	/**
	 * the POST /environments/{{envID}}/riskEvaluations operation to create a new
	 * risk evaluation resource associated with the environment specified in the
	 * request URL. The request body defines the event that is processed for risk
	 * evaluation.
	 *
	 * @param accessToken The {@link AccessToken} from
	 * @param worker      The worker
	 * @param body        The request body
	 * @return The response from /environments/{{envID}}/riskEvaluations operation
	 * @throws Exception When API response != 201
	 */
	protected JsonValue evaluate(AccessToken accessToken, TNTPPingOneConfig worker, JsonValue body) throws Exception {
		Request request = null;
		try {
			URI uri = URI.create(PingOneProtectEvaluationNode.endpoint + worker.environmentRegion().getDomainSuffix() + "/v1/environments/" + worker.environmentId()
					+ "/riskEvaluations");
			request = new Request();
			request.setUri(uri).setMethod(HttpConstants.Methods.POST);
			request.getEntity().setJson(body);
			addAuthorizationHeader(request, accessToken);
			Response response = handler.handle(new RootContext(), request).getOrThrow();
			if (response.getStatus() == Status.CREATED) {
				return json(response.getEntity().getJson());
			} else {
				throw new Exception("PingOne Create Risk Evaluation API response with error." + response.getStatus()
						+ "-" + response.getEntity().getString());
			}
		} catch (Exception e) {
			throw new Exception("Failed to create risk evaluation", e);
		} 
	}
	
	
	/**
	 * Use PUT /environments/{{envID}}/riskEvaluations/{{riskID}}/event to update
	 * the risk evaluation configuration, and to modify the completion status of the
	 * resource when the risk evaluation is still in progress.
	 *
	 * @param accessToken The {@link AccessToken}
	 * @param worker      The worker
	 * @param riskEvalId  The risk evaluation id
	 * @param status      The completion status
	 * @return The response from /environments/{{envID}}/riskEvaluations operation
	 * @throws Exception When API response != 200
	 */
	protected JsonValue event(AccessToken accessToken, TNTPPingOneConfig worker, String riskEvalId, String status)
			throws Exception {
		Request request = null;
		
		try {
			URI uri = URI.create(PingOneProtectEvaluationNode.endpoint + worker.environmentRegion().getDomainSuffix() + "/v1/environments/" + worker.environmentId()
					+ "/riskEvaluations/" + riskEvalId + "/event");
			request = new Request();
			request.setUri(uri).setMethod(HttpConstants.Methods.PUT);
			request.getEntity().setJson(object(field("completionStatus", status)));
			addAuthorizationHeader(request, accessToken);
			Response response = handler.handle(new RootContext(), request).getOrThrow();
			if (response.getStatus() == Status.OK) {
				return json(response.getEntity().getJson());
			} else {
				throw new Exception("PingOne Update Risk Evaluation API response with error." + response.getStatus()
						+ "-" + response.getEntity().getString());
			}
		} catch (Exception e) {
			throw new Exception("Failed to update risk evaluation", e);
		} 
	}
	

	private void addAuthorizationHeader(Request request, AccessToken accessToken) throws MalformedHeaderException {
		AuthorizationHeader header = new AuthorizationHeader();
		BearerToken bearerToken = new BearerToken(accessToken.getTokenId());
		header.setRawValue(BearerToken.NAME + " " + bearerToken);
		request.addHeaders(header);
	}
	

}
