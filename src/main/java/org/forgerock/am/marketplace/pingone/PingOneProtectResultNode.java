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

import java.util.Optional;
import java.util.function.Supplier;

import javax.inject.Inject;

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
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.util.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;

/**
 * Update the risk evaluation configuration, and to modify the completion status of the
 * resource when the risk evaluation is still in progress.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
    configClass = PingOneProtectResultNode.Config.class,
    tags = {"risk"})
public class PingOneProtectResultNode extends SingleOutcomeNode {
    private static final Logger logger = LoggerFactory.getLogger(PingOneProtectResultNode.class);
    /**
     * SharedState variable name to store the evaluation completion result.
     */
    @VisibleForTesting
    static final String RISK_EVALUATE_COMPLETION_RESULT =
        PingOneProtectResultNode.class.getSimpleName() + ".RESULT";

    private final Config config;
    private final Realm realm;
    private final PingOneWorkerService pingOneWorkerService;
    private final PingOneProtectService pingOneProtectService;

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * The state of the transaction. Options are FAILED and SUCCESS.
         *
         * @return The state of the transaction. Options are FAILED and SUCCESS.
         */
        @Attribute(order = 100)
        default CompletionStatus status() {
            return CompletionStatus.SUCCESS;
        }

    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of
     * other classes from the plugin.
     *
     * @param config The Node configuration.
     * @param realm The current realm.
     * @param pingOneWorkerService The {@link PingOneWorkerService} instance.
     * @param pingOneProtectService The {@link PingOneProtectService} instance.
     */
    @Inject
    public PingOneProtectResultNode(@Assisted Config config, @Assisted Realm realm,
        PingOneWorkerService pingOneWorkerService, PingOneProtectService pingOneProtectService) {
        this.config = config;
        this.realm = realm;
        this.pingOneWorkerService = pingOneWorkerService;
        this.pingOneProtectService = pingOneProtectService;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        NodeState state = context.getStateFor(this);
        JsonValue riskId = state.get(RISK_EVALUATE_ID);
        JsonValue workerId = state.get(PINGONE_PROTECT_WORKER);
        if (riskId != null && workerId != null) {
            try {
                Optional<PingOneWorkerConfig.Worker> opt = pingOneWorkerService.getWorker(realm, workerId.asString());
                PingOneWorkerConfig.Worker worker = opt.orElseThrow((Supplier<IllegalArgumentException>) () -> {
                    throw new IllegalArgumentException("PingOne Worker not found: " + workerId.asString());
                });

                AccessToken accessToken = pingOneWorkerService.getAccessToken(realm, worker);
                pingOneProtectService.event(accessToken, worker, riskId.asString(), config.status().name());

                state.putShared(RISK_EVALUATE_COMPLETION_RESULT, true);

            } catch (IllegalArgumentException | PingOneWorkerException e) {
                //Best effort to update the result, we don't want to fail the Journey
                logger.warn("Failed to update Risk Evaluation result.", e);
                state.putShared(RISK_EVALUATE_COMPLETION_RESULT, false);
            }
        } else {
            //Best effort to update the result, we don't want to fail the Journey
            state.putShared(RISK_EVALUATE_COMPLETION_RESULT, false);
            logger.warn("Failed to update Risk Evaluation result, riskId or workerId not found");
        }
        return goToNext().build();

    }

    @Override
    public InputState[] getInputs() {
        return new InputState[]{
            new InputState(PINGONE_PROTECT_WORKER),
            new InputState(RISK_EVALUATE_ID),
        };
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{
            new OutputState(RISK_EVALUATE_COMPLETION_RESULT)
        };
    }
}