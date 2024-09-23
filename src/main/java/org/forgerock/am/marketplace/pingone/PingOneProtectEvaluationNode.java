/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.marketplace.pingone;

import static java.util.Collections.emptyList;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.OutcomeProvider.ERROR;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.OutcomeProvider.EXCEED_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.OutcomeProvider.HIGH_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.OutcomeProvider.LOW_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.OutcomeProvider.MEDIUM_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.StateKey.PINGONE_PROTECT_WORKER;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.StateKey.RISK_EVALUATE_ID;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.StateKey.RISK_EVALUATE_RESULT;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.openam.auth.nodes.helpers.AuthNodeUserIdentityHelper.getAMIdentity;

import java.math.BigDecimal;
import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import com.sun.identity.authentication.spi.MetadataCallback;
import org.apache.commons.lang3.StringUtils;
import org.forgerock.am.identity.application.LegacyIdentityService;
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
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.validators.DecimalValidator;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneUtility;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.http.HttpConstants;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.annotations.VisibleForTesting;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Strings;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdConstants;
import com.sun.identity.idm.IdRepoException;

/**
 * A node that integrate with PingOne Protect Evaluation, which calculate the
 * risk from client signals.
 */
@Node.Metadata(outcomeProvider = PingOneProtectEvaluationNode.OutcomeProvider.class, configClass = PingOneProtectEvaluationNode.Config.class, tags = {
		"marketplace", "trustnetwork" })
public class PingOneProtectEvaluationNode extends SingleOutcomeNode {

	public static final String REST_PINGONE_CLIENT_SECRET = "am.services.pingone.worker.%s.clientsecret";
	protected static String endpoint = "https://api.pingone";
	private static final Logger logger = LoggerFactory.getLogger(PingOneProtectEvaluationNode.class);
	private String loggerPrefix = "[PingOneProtectEvaluationNode]" + PingOneProtectPlugin.logAppender;

	/**
	 * State Key defined by this Node.
	 */
	static final class StateKey {

		private StateKey() {
		}

		/**
		 * State variable name for storing the risk evaluation result.
		 */
		@VisibleForTesting
		static final String RISK_EVALUATE_RESULT = PingOneProtectEvaluationNode.class.getSimpleName() + ".RISK";
		/**
		 * State variable name for storing the riskEvaluateId.
		 */
		static final String RISK_EVALUATE_ID = PingOneProtectEvaluationNode.class.getSimpleName() + ".riskEvalID";
		/**
		 * State variable name for storing the PingOne Worker ID.
		 */
		static final String PINGONE_PROTECT_WORKER = PingOneProtectEvaluationNode.class.getSimpleName() + ".worker";
	}

	private static final String RESULT = "result";
	private static final String RECOMMENDED_ACTIONS = "recommendedActions";
	private static final String RECOMMENDED_ACTION = "recommendedAction";

	private static final String ID = "id";
	private static final String LEVEL = "level";
	private static final String HIGH = "HIGH";
	private static final String MEDIUM = "MEDIUM";
	private static final String LOW = "LOW";
	/**
	 * Audit attribute for risk evaluate id.
	 */
	@VisibleForTesting
	static final String PINGONE_RISK_EVALUATE_ID = "PINGONE_RISK_EVALUATE_ID";
	/**
	 * Audit attribute for PingOne environment id.
	 */
	@VisibleForTesting
	static final String PINGONE_RISK_ENV_ID = "PINGONE_RISK_ENV_ID";
	private final Config config;
	private TNTPPingOneConfig tntpPingOneConfig;

	private final LegacyIdentityService identityService;
	private final CoreWrapper coreWrapper;

	private final Realm realm;

	// audit attributes
	// private String riskEvaluateId;
	// private String envId;

	/**
	 * Configuration for the node.
	 */
	public interface Config {

		/**
		 * The Configured service
		 */
		@Attribute(order = 100, choiceValuesClass = TNTPPingOneConfigChoiceValues.class)
		default String tntpPingOneConfigName() {
			return TNTPPingOneConfigChoiceValues.createTNTPPingOneConfigName("Global Default");
		};

		/**
		 * The ID of the target application.
		 *
		 * @return The ID of the target application.
		 */
		@Attribute(order = 200)
		Optional<String> targetResourceID();

		/**
		 * UUID of the policy set to trigger.
		 *
		 * @return UUID of the policy set to trigger
		 */
		@Attribute(order = 300)
		Optional<String> riskPolicySetID();

		/**
		 * The type of flow for which the risk evaluation is being carried out.
		 *
		 * @return The type of flow for which the risk evaluation is being carried out
		 */
		@Attribute(order = 400)
		default FlowType flowType() {
			return FlowType.AUTHENTICATION;
		}

		/**
		 * The device sharing type. Options are UNSPECIFIED, SHARED, and PRIVATE.
		 *
		 * @return The device sharing type. Options are UNSPECIFIED, SHARED, and
		 *         PRIVATE.
		 */
		@Attribute(order = 500)
		default DeviceSharingType deviceSharingType() {
			return DeviceSharingType.SHARED;
		}

		/**
		 * The type of user associated with the event. The possible values are PING_ONE
		 * and EXTERNAL.
		 *
		 * @return The type of user associated with the event. The possible values are
		 *         PING_ONE and EXTERNAL.
		 */
		@Attribute(order = 600)
		default UserType userType() {
			return UserType.EXTERNAL;
		}

		/**
		 * The score limit, scoring higher than this value causes exceed outcome.
		 *
		 * @return The score limit
		 */
		@Attribute(order = 700, requiredValue = true, validators = { DecimalValidator.class })
		default String scoreThreshold() {
			return "300";
		}

		/**
		 * The recommended course of action based on the evaluation. Currently used only
		 * for policies that include a bot detection predictor. If recommendedAction is
		 * included in the response, the only value that is used is BOT_MITIGATION,
		 * meaning that you should take steps to handle a scenario where a bot is
		 * involved.
		 *
		 * @return The recommended Actions
		 */
		@Attribute(order = 800)
		default List<String> recommendedActions() {
			return emptyList();
		}

		/**
		 * Instruct the client to pause the behavioural collection.
		 *
		 * @return True to pause collecting behavioral data.
		 */
		@Attribute(order = 900)
		default boolean pauseBehavioralData() {
			return true;
		}

		/**
		 * Context State variable name to override the default user identifier.
		 *
		 * @return The context state variable name.
		 */
		@Attribute(order = 1000)
		default Optional<String> userId() {
			return Optional.empty();
		}

		/**
		 * Context State variable name to override the default username.
		 *
		 * @return The context state variable name.
		 */
		@Attribute(order = 1100)
		default Optional<String> username() {
			return Optional.empty();
		}

		/**
		 * Store evaluate result.
		 *
		 * @return True to store the result in Transient State
		 */
		@Attribute(order = 1200)
		default boolean storeEvaluateResult() {
			return false;
		}

		/**
		 * Specify whether to return a script or metadata callback.
		 *
		 * @return {@literal true} if return as a script.
		 */
		@Attribute(order = 1300)
		default boolean useScript() {
			return true;
		}
	}

	/**
	 * Create the node using Guice injection. Just-in-time bindings can be used to
	 * obtain instances of other classes from the plugin.
	 *
	 * @param config                The Node configuration.
	 * @param realm                 The current realm.
	 * @param identityService       Identity Service instance
	 * @param coreWrapper           The core wrapper instance
	 */
	@Inject
	public PingOneProtectEvaluationNode(@Assisted Config config, @Assisted Realm realm,
			LegacyIdentityService identityService, CoreWrapper coreWrapper) {
		this.config = config;
		this.realm = realm;
		this.identityService = identityService;
		this.coreWrapper = coreWrapper;
		this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {

		try {
			if (context.hasCallbacks()) {

				String signals = getSignalsFromCallback(context);

				if (callbackHasError(context)) {
					return Action.goTo(ERROR).build();
				}

				TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
				String accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);

				NodeState state = context.getStateFor(this);

				JsonValue result = evaluate(accessToken, tntpPingOneConfig,
						getRequestBody(context, state, signals));

				// Put information to sharedState so that the PingOneProtectResult will update
				// the risk result.
				state.putShared(RISK_EVALUATE_ID, result.get(ID));
				// state.putShared(PINGONE_PROTECT_WORKER, tntpPingOneConfig.id());
				state.putShared(PINGONE_PROTECT_WORKER, config.tntpPingOneConfigName());

				// Log Audit attribute
				// riskEvaluateId = result.get(ID).asString();
				// envId = tntpPingOneConfig.environmentId();

				// Store to transient state instead of sharedstate, putting to sharedstate will
				// increase the size of
				// authId token
				if (config.storeEvaluateResult()) {
					state.putTransient(RISK_EVALUATE_RESULT, result);
				}

				// Score Threshold takes the highest precedence.
				BigDecimal scoreLimit = new BigDecimal(config.scoreThreshold());
				if (scoreLimit.compareTo(BigDecimal.ZERO) > 0 && result.get(RESULT).isDefined("score")) {
					double score = result.get(RESULT).get("score").asDouble();
					if (BigDecimal.valueOf(score).compareTo(scoreLimit) > 0) {
						return Action.goTo(EXCEED_OUTCOME_ID).build();
					}
				}

				// If the recommended Action outcome is not defined, fallback to level
				if (result.get(RESULT).isDefined(RECOMMENDED_ACTION)) {
					String advice = result.get(RESULT).get(RECOMMENDED_ACTION).asString();
					if (config.recommendedActions().contains(advice)) {
						return Action.goTo(advice).build();
					}
					logger.warn("Outcome not found for recommended action {}", advice);
				}

				if (result.get(RESULT).isDefined(LEVEL)) {
					return getAction(result.get(RESULT).get(LEVEL).asString());
				}

				throw new IllegalArgumentException("Evaluation result is invalid" + result);
			} else {
				return getCallback();
			}
		} catch (Exception e) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(e);

			logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
			context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + e.getMessage());
			context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
			return Action.goTo(ERROR).withHeader("Error occurred").withErrorMessage(e.getMessage()).build();
		}
	}

	private String getSignalsFromCallback(TreeContext context) {
		AtomicReference<String> signals = new AtomicReference<>();
		if (config.useScript()) {
			signals.set(context.getCallback(HiddenValueCallback.class)
					.map(HiddenValueCallback::getValue)
					.filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput))
					.orElse(null));
		} else {
			context.getCallbacks(HiddenValueCallback.class).forEach(callback -> {
				if (callback.getId().equals("pingone_risk_evaluation_signals")) {
					signals.set(callback.getValue());
				}
			});
		}
		return signals.get();
	}

	private boolean callbackHasError(TreeContext context) {
		AtomicBoolean hasError = new AtomicBoolean(false);
		if (config.useScript()) {
			HiddenValueCallback clientErrorCallback = context.getCallback(HiddenValueCallback.class).get();
			Optional<String> clientError = Optional.ofNullable(clientErrorCallback.getValue());
			if (clientError.isPresent()) {
				logClientError(context, clientError.get());
				hasError.set(true);
			}
		} else {
			context.getCallbacks(HiddenValueCallback.class).forEach(callback -> {
				if (callback.getId().equals("clientError") && StringUtils.isNotEmpty(callback.getValue())) {
					logClientError(context, callback.getValue());
					hasError.set(true);
				}
			});
		}
		return hasError.get();
	}

	private void logClientError(TreeContext context, String clientError) {
		logger.error("{}Client error: {}", loggerPrefix, clientError);
		context.getStateFor(this).putTransient(loggerPrefix + "ClientError", new Date() + ": " + clientError);
	}


	private Action getAction(String result) throws Exception {
		switch (result) {
		case HIGH: {
			return Action.goTo(HIGH_OUTCOME_ID).build();
		}
		case MEDIUM: {
			return Action.goTo(MEDIUM_OUTCOME_ID).build();
		}
		case LOW: {
			return Action.goTo(LOW_OUTCOME_ID).build();
		}
		default:
			throw new IllegalStateException("Unexpected level value: " + result);
		}
	}

	private JsonValue getRequestBody(TreeContext context, NodeState state, String signals)
			throws JsonProcessingException {

		Event.Root root = new Event.Root();
		Event event = new Event();
		if (config.targetResourceID().isPresent()) {
			Event.TargetResource targetResource = new Event.TargetResource(config.targetResourceID().get());
			event.setTargetResource(targetResource);
		}
		event.setIp(context.request.clientIp);
		event.setFlow(new Event.Flow(config.flowType().name()));
		event.setUser(prepareUser(context, state));
		if (StringUtils.isNotEmpty(signals)) {
			event.setSdk(new Event.Sdk(new Event.Signals(signals)));
		}
		event.setSharingType(config.deviceSharingType().name());
		List<String> userAgents = context.request.headers.get("User-Agent");
		if (userAgents != null && !userAgents.isEmpty()) {
			event.setBrowser(new Event.Browser(userAgents.get(0)));
		}

		root.setEvent(event);

		if (config.riskPolicySetID().isPresent()) {
			root.setRiskPolicySet(new Event.RiskPolicySet(config.riskPolicySetID().get()));
		}

		return JsonValueBuilder.toJsonValue(JsonValueBuilder.getObjectMapper().writeValueAsString(root));
	}

	private Event.User prepareUser(TreeContext context, NodeState state) {

		Event.User user = null;
		String userId = null;
		String username = null;

		if (config.userId().isPresent()) {
			JsonValue value = state.get(config.userId().get());
			if (value != null) {
				userId = value.asString();
			}
		} else {
			user = getAMIdentityUser(context, state);
			userId = user.getId();
		}

		if (config.username().isPresent()) {
			JsonValue value = state.get(config.username().get());
			if (value != null) {
				username = value.asString();
			}
		} else {
			if (user == null) {
				user = getAMIdentityUser(context, state);
			}
			username = user.getName();
		}

		return new Event.User(userId, username, config.userType().name());

	}

	private Event.User getAMIdentityUser(TreeContext context, NodeState state) {
		Optional<AMIdentity> user = getAMIdentity(context.universalId, state, identityService, coreWrapper);
		if (user.isEmpty()) {
			String username = state.isDefined(USERNAME) ? state.get(USERNAME).asString() : null;
			return new Event.User(context.universalId.orElse(null), username, config.userType().name());
		} else {
			AMIdentity identity = user.get();
			String username = identity.getName();
			try {
				Set<String> usernameAttributeValue = identity.getAttribute(IdConstants.USERNAME);
				if (usernameAttributeValue.isEmpty()) {
					identity.getAttributes(); // Refresh the cache
					usernameAttributeValue = identity.getAttribute(IdConstants.USERNAME);
				}
				if (CollectionUtils.isNotEmpty(usernameAttributeValue)) {
					username = usernameAttributeValue.iterator().next();
				}
			} catch (IdRepoException | SSOException e) {
				logger.warn("Unable to get username attribute for identity '{}', returning username for Account Name",
						identity.getName(), e);
			}
			return new Event.User(user.get().getUniversalId(), username, config.userType().name());
		}
	}

	private Action getCallback() throws Exception {

		String clientScript = ScriptHelper.readJS(ScriptHelper.sdkJsPathSigTemplate);

		List<Callback> callbacks = new ArrayList<>();

		if (config.useScript()) {
			callbacks.add(ScriptHelper.getSigCallback(clientScript));
			callbacks.add(new HiddenValueCallback("clientScriptOutputData"));
		} else {
			JsonValue callbackData = JsonValue.json(JsonValue.object());
			callbackData.put("_type", "PingOneProtect");
			callbackData.put("_action", "protect_risk_evaluation");  // TODO check if it is evaluate or evaluation
			callbackData.put("envId", tntpPingOneConfig.environmentId());
			callbackData.put("pauseBehavioralData", config.pauseBehavioralData());
			callbacks.add(new MetadataCallback(callbackData));
			callbacks.add(new HiddenValueCallback("pingone_risk_evaluation_signals", ""));
			callbacks.add(new HiddenValueCallback("clientError", ""));
		}

		return Action.send(callbacks).build();
	}

	/**
	 * Provides the authentication node's set of outcomes.
	 */
	public static class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
		private static final String BUNDLE = PingOneProtectEvaluationNode.class.getName();
		/**
		 * High Risk outcome.
		 */
		static final String HIGH_OUTCOME_ID = "high";
		/**
		 * Medium Risk outcome.
		 */
		@VisibleForTesting
		static final String MEDIUM_OUTCOME_ID = "medium";
		/**
		 * Low Risk outcome.
		 */
		@VisibleForTesting
		static final String LOW_OUTCOME_ID = "low";
		/**
		 * Exceed score threshold outcome.
		 */
		@VisibleForTesting
		static final String EXCEED_OUTCOME_ID = "exceed";

		/**
		 * Client Error outcome.
		 */
		@VisibleForTesting
		static final String ERROR = "error";

		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes)
				throws NodeProcessException {

			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
					PingOneProtectEvaluationNode.OutcomeProvider.class.getClassLoader());

			ArrayList<Outcome> outcomes = new ArrayList<>();

			outcomes.add(new Outcome(HIGH_OUTCOME_ID, bundle.getString(HIGH_OUTCOME_ID)));
			outcomes.add(new Outcome(MEDIUM_OUTCOME_ID, bundle.getString(MEDIUM_OUTCOME_ID)));
			outcomes.add(new Outcome(LOW_OUTCOME_ID, bundle.getString(LOW_OUTCOME_ID)));
			outcomes.add(new Outcome(EXCEED_OUTCOME_ID, bundle.getString(EXCEED_OUTCOME_ID)));
			if (nodeAttributes.isNotNull()) {
				// nodeAttributes is null when the node is created
				nodeAttributes.get(RECOMMENDED_ACTIONS).required().asList(String.class).stream()
						.map(outcome -> new Outcome(outcome, outcome)).forEach(outcomes::add);
			}
			outcomes.add(new Outcome(ERROR, bundle.getString(ERROR)));

			return outcomes;
		}
	}

	@Override
	public InputState[] getInputs() {
		List<InputState> inputs = new ArrayList<>();
		if (config.userId().isPresent()) {
			inputs.add(new InputState(config.userId().get(), false));
		}
		if (config.username().isPresent()) {
			inputs.add(new InputState(config.username().get(), false));
		}
		inputs.add(new InputState(USERNAME, false));
		inputs.add(new InputState(REALM, false));
		return inputs.toArray(new InputState[] {});
	}

	/*
	 * @Override public OutputState[] getOutputs() { return new OutputState[] { new
	 * OutputState(RISK_EVALUATE_ID, singletonMap("*", false)), new
	 * OutputState(PINGONE_PROTECT_WORKER, singletonMap("*", false)), new
	 * OutputState(RISK_EVALUATE_RESULT, singletonMap("*", false)) }; }
	 * 
	 * @Override public JsonValue getAuditEntryDetail() { return
	 * json(object(field(PINGONE_RISK_EVALUATE_ID, riskEvaluateId),
	 * field(PINGONE_RISK_ENV_ID, envId))); }
	 */

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
	public JsonValue evaluate(String accessToken, TNTPPingOneConfig worker, JsonValue body) throws Exception {
		Request request = null;
		HttpClientHandler handler = null;
		try {
			handler = new HttpClientHandler();
			URI uri = URI.create(endpoint + worker.environmentRegion().getDomainSuffix() + "/v1/environments/" + worker.environmentId()
					+ "/riskEvaluations");
			request = new Request().setUri(uri).setMethod(HttpConstants.Methods.POST);
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

	private void addAuthorizationHeader(Request request, String accessToken) throws MalformedHeaderException {
		AuthorizationHeader header = new AuthorizationHeader();
		BearerToken bearerToken = new BearerToken(accessToken);
		header.setRawValue(BearerToken.NAME + " " + bearerToken);
		request.addHeaders(header);
	}

}