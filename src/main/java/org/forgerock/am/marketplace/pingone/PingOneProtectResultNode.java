/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.marketplace.pingone;

import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.StateKey.PINGONE_PROTECT_WORKER;
import static org.forgerock.am.marketplace.pingone.PingOneProtectEvaluationNode.StateKey.RISK_EVALUATE_ID;

import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

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
		"marketplace", "trustnetwork" })
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
	private final Helper client;
	
	
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
	 */
	@Inject
	public PingOneProtectResultNode(@Assisted Config config, @Assisted Realm realm, Helper client) {
		this.config = config;
		this.realm = realm;
		this.client = client;
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
				client.event(accessToken, tntpPingOneConfig, riskId.asString(), config.status().name());
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