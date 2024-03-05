/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.am.marketplace.pingone;

import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.StateKey.PINGONE_PROTECT_WORKER;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.StateKey.RISK_EVALUATE_ID;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.net.URI;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.http.header.AuthorizationHeader;
import org.forgerock.http.header.MalformedHeaderException;
import org.forgerock.http.header.authorization.BearerToken;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneUtility;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.http.HttpConstants;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.annotations.VisibleForTesting;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;

/**
 * Update the risk evaluation configuration, and to modify the completion status
 * of the resource when the risk evaluation is still in progress.
 */
@Node.Metadata(outcomeProvider = PingOneProtectResultNode.PingOneProtectResultNodeOutcomeProvider.class, configClass = PingOneProtectResultNode.Config.class, tags = {
		"risk" })
public class PingOneProtectResultNode extends AbstractDecisionNode  {
	private static final Logger logger = LoggerFactory.getLogger(PingOneProtectResultNode.class);
	private String loggerPrefix = "[PingOneProtectResultNode]" + PingOneProtectPlugin.logAppender;
	/**
	 * SharedState variable name to store the evaluation completion result.
	 */
	@VisibleForTesting
	static final String RISK_EVALUATE_COMPLETION_RESULT = PingOneProtectResultNode.class.getSimpleName() + ".RESULT";

	private final Config config;
	private final Realm realm;
	
	
	private static final String NEXT = "NEXT";
	private static final String ERROR = "ERROR";
	private static final String BUNDLE = PingOneProtectResultNode.class.getName();
	/**
	 * Configuration for the node.
	 */
	public interface Config {
		
		

		/**
		 * The state of the transaction. Options are FAILED and SUCCESS.
		 *
		 * @return The state of the transaction. Options are FAILED and SUCCESS.
		 */
		@Attribute(order = 200)
		default CompletionStatus status() {
			return CompletionStatus.SUCCESS;
		}		
		
	}

	/**
	 * Create the node using Guice injection. Just-in-time bindings can be used to
	 * obtain instances of other classes from the plugin.
	 *
	 * @param config                The Node configuration.
	 * @param realm                 The current realm.
	 * @param pingOneWorkerService  The {@link PingOneWorkerService} instance.
	 * @param pingOneProtectService The {@link PingOneProtectService} instance.
	 */
	@Inject
	public PingOneProtectResultNode(@Assisted Config config, @Assisted Realm realm) {
		this.config = config;
		this.realm = realm;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		NodeState state = context.getStateFor(this);
		try {
			
			JsonValue riskId = state.get(RISK_EVALUATE_ID);
			JsonValue worker = state.get(PINGONE_PROTECT_WORKER);
			if (riskId != null && worker != null) {
				TNTPPingOneConfig tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(worker.asString());
				TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
				AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
				event(accessToken, tntpPingOneConfig, riskId.asString(), config.status().name());
				state.putShared(RISK_EVALUATE_COMPLETION_RESULT, true);
			} else {
				// Best effort to update the result, we don't want to fail the Journey
				state.putShared(RISK_EVALUATE_COMPLETION_RESULT, false);
				logger.warn("Failed to update Risk Evaluation result, riskId or workerId not found");
			}
			return Action.goTo(NEXT).build();
		} catch (Exception e) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(e);

			logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
			context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + e.getMessage());
			context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
			state.putShared(RISK_EVALUATE_COMPLETION_RESULT, false);
			return Action.goTo(ERROR).withHeader("Error occurred").withErrorMessage(e.getMessage()).build();
			
		}

	}
	
	/**
	 * Use PUT /environments/{{envID}}/riskEvaluations/{{riskID}}/event to update
	 * the risk evaluation configuration, and to modify the completion status of the
	 * resource when the risk evaluation is still in progress.
	 *
	 * @param accessToken The {@link AccessToken} from {@link PingOneProtectService}
	 * @param worker      The worker {@link PingOneWorkerConfig}
	 * @param riskEvalId  The risk evaluation id
	 * @param status      The completion status
	 * @return The response from /environments/{{envID}}/riskEvaluations operation
	 * @throws PingOneWorkerException When API response != 200
	 */
	public JsonValue event(AccessToken accessToken, TNTPPingOneConfig worker, String riskEvalId, String status)
			throws Exception {
		Request request = null;
		HttpClientHandler handler = null;
		try {
			handler = new HttpClientHandler();
			URI uri = URI.create(PingOneProtectEvaluationNode.endpoint + worker.environmentRegion().getDomainSuffix() + "/v1/environments/" + worker.environmentId()
					+ "/riskEvaluations/" + riskEvalId + "/event");
			request = new Request().setUri(uri).setMethod(HttpConstants.Methods.PUT);
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
		} finally {
			if (handler != null) {
				try {
					handler.close();
				} catch (Exception e) {
					// DO NOTHING
				}
			}

			if (request != null) {
				try {
					request.close();
				} catch (Exception e) {
					// DO NOTHING
				}
			}
		}
	}
	
	
	private void addAuthorizationHeader(Request request, AccessToken accessToken) throws MalformedHeaderException {
		AuthorizationHeader header = new AuthorizationHeader();
		BearerToken bearerToken = new BearerToken(accessToken.getTokenId());
		header.setRawValue(BearerToken.NAME + " " + bearerToken);
		request.addHeaders(header);
	}
	
	
	/**
	 * Defines the possible outcomes from this node.
	 */
	public static class PingOneProtectResultNodeOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, PingOneProtectResultNodeOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(
					new Outcome(NEXT, bundle.getString("NextOutcome")), 
					new Outcome(ERROR, bundle.getString("ErrorOutcome")));
		}
	}
	
	
}