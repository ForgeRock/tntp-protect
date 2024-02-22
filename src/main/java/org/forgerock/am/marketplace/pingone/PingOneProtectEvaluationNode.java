/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.am.marketplace.pingone;


import static java.util.Collections.emptyList;
import static java.util.Collections.singletonMap;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.OutcomeProvider.CLIENT_ERROR_OUTCOME_ID;
import static org.forgerock.openam.auth.nodes.helpers.AuthNodeUserIdentityHelper.getAMIdentity;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.OutcomeProvider.EXCEED_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.OutcomeProvider.FAILURE_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.OutcomeProvider.HIGH_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.OutcomeProvider.LOW_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.OutcomeProvider.MEDIUM_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.StateKey.PINGONE_PROTECT_WORKER;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.StateKey.RISK_EVALUATE_ID;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.StateKey.RISK_EVALUATE_RESULT;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;

import javax.inject.Inject;

import org.apache.commons.lang3.StringUtils;
import org.forgerock.am.identity.application.LegacyIdentityService;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.validators.DecimalValidator;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.am.marketplace.pingone.PingOneProtectService;
import org.forgerock.am.marketplace.pingone.PingOneWorkerConfig;
import org.forgerock.am.marketplace.pingone.PingOneWorkerService;
import org.forgerock.am.marketplace.pingone.PingOneWorker;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.util.annotations.VisibleForTesting;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdConstants;
import com.sun.identity.idm.IdRepoException;

/**
 * A node that integrate with PingOne Protect Evaluation, which calculate the risk from client signals.
 */
@Node.Metadata(outcomeProvider = PingOneProtectEvaluationNode.OutcomeProvider.class,
    configClass = PingOneProtectEvaluationNode.Config.class,
    tags = {"risk", "sdk"})
public class PingOneProtectEvaluationNode extends SingleOutcomeNode {
	
	
	public static final String REST_PINGONE_CLIENT_SECRET = "am.services.pingone.worker.%s.clientsecret";

    private static final Logger logger = LoggerFactory.getLogger(PingOneProtectEvaluationNode.class);

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
    private final LegacyIdentityService identityService;
    private final CoreWrapper coreWrapper;
    private final PingOneWorkerService pingOneWorkerService;
    private final PingOneProtectService pingOneProtectService;

    private final Realm realm;

    //audit attributes
    private String riskEvaluateId;
    private String envId;

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * Reference to the PingOne Worker App.
         *
         * @return The PingOne Worker App.
         */
        @Attribute(order = 100, requiredValue = true)
        @PingOneWorker
        PingOneWorkerConfig.Worker pingOneWorker();

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
         * @return The device sharing type. Options are UNSPECIFIED, SHARED, and PRIVATE.
         */
        @Attribute(order = 500)
        default DeviceSharingType deviceSharingType() {
            return DeviceSharingType.SHARED;
        }

        /**
         * The type of user associated with the event. The possible values are PING_ONE and EXTERNAL.
         *
         * @return The type of user associated with the event. The possible values are PING_ONE and EXTERNAL.
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
        @Attribute(order = 700, requiredValue = true, validators = {DecimalValidator.class})
        default String scoreThreshold() {
            return "300";
        }

        /**
         * The recommended course of action based on the evaluation.
         * Currently used only for policies that include a bot detection predictor.
         * If recommendedAction is included in the response, the only value that is used is BOT_MITIGATION,
         * meaning that you should take steps to handle a scenario where a bot is involved.
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

    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of
     * other classes from the plugin.
     *
     * @param config The Node configuration.
     * @param realm The current realm.
     * @param identityService Identity Service instance
     * @param coreWrapper The core wrapper instance
     * @param pingOneWorkerService The {@link PingOneWorkerService} instance.
     * @param pingOneProtectService The {@link PingOneProtectService} instance.
     */
    @Inject
    public PingOneProtectEvaluationNode(@Assisted Config config,
        @Assisted Realm realm,
        LegacyIdentityService identityService, CoreWrapper coreWrapper,
        PingOneWorkerService pingOneWorkerService,
        PingOneProtectService pingOneProtectService) {
        this.config = config;
        this.realm = realm;
        this.identityService = identityService;
        this.coreWrapper = coreWrapper;
        this.pingOneWorkerService = pingOneWorkerService;
        this.pingOneProtectService = pingOneProtectService;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        if (context.hasCallbacks()) {
            
        	//TODO fix this
        	//if (StringUtils.isNotEmpty(callback.get().getClientError())) {
            //    return Action.goTo(CLIENT_ERROR_OUTCOME_ID).build();
            //}
            try {
                PingOneWorkerConfig.Worker worker = config.pingOneWorker();

                AccessToken accessToken = pingOneWorkerService.getAccessToken(realm, worker);

                NodeState state = context.getStateFor(this);

                
                //TODO fix this
                JsonValue result = null; //pingOneProtectService.evaluate(accessToken, worker, getRequestBody(context, state, callback.get().getSignals()));

                //Put information to sharedState so that the PingOneProtectResult will update
                //the risk result.
                state.putShared(RISK_EVALUATE_ID, result.get(ID));
                state.putShared(PINGONE_PROTECT_WORKER, config.pingOneWorker().id());

                //Log Audit attribute
                riskEvaluateId = result.get(ID).asString();
                envId = worker.environmentId();

                //Store to transient state instead of sharedstate, putting to sharedstate will increase the size of
                //authId token
                if (config.storeEvaluateResult()) {
                    state.putTransient(RISK_EVALUATE_RESULT, result);
                }

                //Score Threshold takes the highest precedence.
                BigDecimal scoreLimit = new BigDecimal(config.scoreThreshold());
                if (scoreLimit.compareTo(BigDecimal.ZERO) > 0) {
                    double score = result.get(RESULT).get("score").asDouble();
                    if (BigDecimal.valueOf(score).compareTo(scoreLimit) > 0) {
                        return Action.goTo(EXCEED_OUTCOME_ID).build();
                    }
                }

                //If the recommended Action outcome is not defined, fallback to level
                if (result.get(RESULT).isDefined(RECOMMENDED_ACTION)) {
                    String advice = result.get(RESULT).get(RECOMMENDED_ACTION).asString();
                    if (config.recommendedActions().contains(advice)) {
                        return Action.goTo(advice).build();
                    }
                    logger.warn("Outcome not found for recommended action {}", advice);
                }

                return getAction(result.get(RESULT).get(LEVEL).asString());

            } catch (Exception e) {
                logger.warn("PingOne Protect risk evaluation failed", e);
                return Action.goTo(FAILURE_OUTCOME_ID).build();
            }
        } else {
            return getCallback();
        }
    }

    private Action getAction(String result) {
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

    private JsonValue getRequestBody(TreeContext context,
        NodeState state, String signals) throws JsonProcessingException {

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

        return JsonValueBuilder.toJsonValue(JsonValueBuilder
            .getObjectMapper().writeValueAsString(root));
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
        Optional<AMIdentity> user = getAMIdentity(context.universalId, state,
            identityService, coreWrapper);
        if (user.isEmpty()) {
            String username = state.isDefined(USERNAME)
                ? state.get(USERNAME).asString()
                : null;
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

    private Action getCallback() {
    	
    	//TODO fix this
        return null;//Action.send(new PingOneProtectEvaluationCallback(config.pauseBehavioralData())).build();
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
         * Failure outcome.
         */
        @VisibleForTesting
        static final String FAILURE_OUTCOME_ID = "failure";
        /**
         * Client Error outcome.
         */
        @VisibleForTesting
        static final String CLIENT_ERROR_OUTCOME_ID = "clientError";


        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales,
            JsonValue nodeAttributes) throws NodeProcessException {

            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
                PingOneProtectEvaluationNode.OutcomeProvider.class.getClassLoader());

            ArrayList<Outcome> outcomes = new ArrayList<>();

            outcomes.add(new Outcome(HIGH_OUTCOME_ID, bundle.getString(HIGH_OUTCOME_ID)));
            outcomes.add(new Outcome(MEDIUM_OUTCOME_ID, bundle.getString(MEDIUM_OUTCOME_ID)));
            outcomes.add(new Outcome(LOW_OUTCOME_ID, bundle.getString(LOW_OUTCOME_ID)));
            outcomes.add(new Outcome(EXCEED_OUTCOME_ID, bundle.getString(EXCEED_OUTCOME_ID)));
            outcomes.add(new Outcome(FAILURE_OUTCOME_ID, bundle.getString(FAILURE_OUTCOME_ID)));
            if (nodeAttributes.isNotNull()) {
                // nodeAttributes is null when the node is created
                nodeAttributes.get(RECOMMENDED_ACTIONS).required()
                    .asList(String.class)
                    .stream()
                    .map(outcome -> new Outcome(outcome, outcome))
                    .forEach(outcomes::add);
            }
            outcomes.add(new Outcome(CLIENT_ERROR_OUTCOME_ID, bundle.getString(CLIENT_ERROR_OUTCOME_ID)));

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
        return inputs.toArray(new InputState[]{});
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{
            new OutputState(RISK_EVALUATE_ID, singletonMap("*", false)),
            new OutputState(PINGONE_PROTECT_WORKER, singletonMap("*", false)),
            new OutputState(RISK_EVALUATE_RESULT, singletonMap("*", false))
        };
    }

    @Override
    public JsonValue getAuditEntryDetail() {
        return json(object(
            field(PINGONE_RISK_EVALUATE_ID, riskEvaluateId),
            field(PINGONE_RISK_ENV_ID, envId)));
    }

}