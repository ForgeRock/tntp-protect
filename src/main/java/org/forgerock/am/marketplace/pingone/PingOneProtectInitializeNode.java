/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.marketplace.pingone;

import static java.util.Collections.emptyList;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;

/**
 * PingOne Protect Init Node.
 */
@Node.Metadata(outcomeProvider = PingOneProtectInitializeNode.PingOneInitOutcomeProvider.class, configClass = PingOneProtectInitializeNode.Config.class, tags = {
		"marketplace", "trustnetwork" })
public class PingOneProtectInitializeNode extends AbstractDecisionNode {
	private static final Logger logger = LoggerFactory.getLogger(PingOneProtectInitializeNode.class);
	private String loggerPrefix = "[PingOneProtectInitializeNode]" + PingOneProtectPlugin.logAppender;

	private final Config config;
	private TNTPPingOneConfig tntpPingOneConfig;

	private static final String BUNDLE = PingOneProtectInitializeNode.class.getName();
	private static final String NEXT = "NEXT";
	private static final String ERROR = "ERROR";

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
		
        @Attribute(order = 200)
        default String sdkUrl() {
          return "https://apps.pingone.com/signals/web-sdk/5.2.7/signals-sdk.js";
        }

		/**
		 * Enable SDK logs.
		 *
		 * @return True to enable SDK logs
		 */
		@Attribute(order = 300)
		default boolean consoleLogEnabled() {
			return false;
		}

		/**
		 * Metadata blacklist.
		 *
		 * @return Metadata blacklist
		 */
		@Attribute(order = 400)
		default List<String> deviceAttributesToIgnore() {
			return emptyList();
		}

		/**
		 * Custom Host.
		 *
		 * @return The Custom Host.
		 */
		@Attribute(order = 500)
		Optional<String> customHost();

		/**
		 * Lazy Metadata.
		 *
		 * @return True to calculate the metadata only on getData invocation, otherwise
		 *         do it automatically on init. default is false
		 */
		@Attribute(order = 600)
		default boolean lazyMetadata() {
			return false;
		}

		/**
		 * Collect behavioral data.
		 *
		 * @return True to collect behavioral data.
		 */
		@Attribute(order = 700)
		default boolean behavioralDataCollection() {
			return true;
		}

		/**
		 * Disable Hub.
		 *
		 * @return When true, the SDK store the deviceId to the localStorage only and
		 *         won't use an iframe (hub). default is false
		 */
		@Attribute(order = 800)
		default boolean disableHub() {
			return false;
		}

		/**
		 * Device Key Rsync Intervals (In Days).
		 *
		 * @return Number of days used to window the next time the device attestation
		 *         should use the device fallback key. default is 14 days
		 */
		@Attribute(order = 900)
		default Integer deviceKeyRsyncIntervals() {
			return 14;
		}

		/**
		 * Enable Trust.
		 *
		 * @return Tie the device payload to a non-extractable crypto key stored on the
		 *         browser for content authenticity verification
		 */
		@Attribute(order = 1000)
		default boolean enableTrust() {
			return false;
		}

		/**
		 * Disable Tags.
		 *
		 * @return True to skip tag collection. default is false.
		 */
		@Attribute(order = 1100)
		default boolean disableTags() {
			return false;
		}

	}

	/**
	 * Create the node using Guice injection. Just-in-time bindings can be used to
	 * obtain instances of other classes from the plugin.
	 *
	 * @param config The Node configuration.
	 */
	@Inject
	public PingOneProtectInitializeNode(@Assisted Config config, AnnotatedServiceRegistry serviceRegistry) {
		this.config = config;
		this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		try {
			if (context.hasCallbacks()) {
				return Action.goTo(NEXT).build();
			} else {
				return getCallback();
			}
		} catch (Exception e) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(e);
			logger.error(loggerPrefix + "Exception occurred: ", e);
			context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + e.getMessage());
			context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
			return Action.goTo(ERROR).withHeader("Error occurred").withErrorMessage(e.getMessage()).build();
		}

	}

	private Action getCallback() throws Exception {
		String clientScript = Helper.readJS(Helper.sdkJsPathTemplate);

		List<Callback> callbacks = new ArrayList<>();
		callbacks.add(Helper.getScriptedCallback(clientScript, tntpPingOneConfig.environmentId(),
				String.valueOf(config.consoleLogEnabled()), 
				config.deviceAttributesToIgnore().toString(),
				config.customHost().orElse(null), 
				String.valueOf(config.lazyMetadata()),
				String.valueOf(config.behavioralDataCollection()), 
				String.valueOf(config.deviceKeyRsyncIntervals()),
				String.valueOf(config.enableTrust()), 
				String.valueOf(config.disableTags()),
				String.valueOf(config.disableHub()), 
				String.valueOf(config.sdkUrl())));

		return Action.send(callbacks).build();
	}

	/**
	 * Defines the possible outcomes from this node.
	 */
	public static class PingOneInitOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
					PingOneInitOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(NEXT, bundle.getString("NextOutcome")),
					new Outcome(ERROR, bundle.getString("ErrorOutcome")));
		}
	}
}