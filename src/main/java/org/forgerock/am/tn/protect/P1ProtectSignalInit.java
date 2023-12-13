/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2022 ForgeRock AS.
 */


package org.forgerock.am.tn.protect;

import static org.forgerock.openam.auth.node.api.Action.send;

import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;


@Node.Metadata(outcomeProvider = P1ProtectSignalInit.OutcomeProvider.class,
        configClass = P1ProtectSignalInit.Config.class, tags = {"marketplace", "trustnetwork"})
public class P1ProtectSignalInit extends AbstractDecisionNode {


    private final Logger logger = LoggerFactory.getLogger(P1ProtectSignalInit.class);
    private String loggerPrefix = "[P1ProtectSignalInit]" + P1ProtectSignalInitPlugin.logAppender;

    private final Config config;
    private static final String BUNDLE = P1ProtectSignalInit.class.getName();

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * URL of the apps.pingone.com script to load
         */
        @Attribute(order = 100)
        default String url() {
          return "https://apps.pingone.com/signals/web-sdk/5.2.7/signals-sdk.js";
        }

        @Attribute(order = 200)
        default boolean bdc() {
          return true;
        }

        @Attribute(order = 300)
        default boolean dbg() {
          return false;
        }



    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */


    @Inject
    public P1ProtectSignalInit(@Assisted Config config) throws NodeProcessException {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        try {
            if(config.dbg()) {
              logger.debug(loggerPrefix + "Node started");
            }

            NodeState ns = context.getStateFor(this);
            ns.putShared("PingOneProtectInit","true");

            Optional<String> result = context.getCallback(HiddenValueCallback.class).map(HiddenValueCallback::getValue).filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput));

            if (result.isPresent())  {
              /*JsonValue newSharedState = context.sharedState.copy();
              newSharedState.put("p1ProtectInit", "true");
              return goTo(true).replaceSharedState(newSharedState).build();*/
              return Action.goTo("true").build();
            } else {
                if(config.dbg()) {
                  logger.debug(loggerPrefix + "Sending callbacks");
                }
                String clientSideScriptExecutorFunction = createClientSideScript(config.url(), config.bdc(), config.dbg());
                ScriptTextOutputCallback scriptAndSelfSubmitCallback =
                        new ScriptTextOutputCallback(clientSideScriptExecutorFunction);
                HiddenValueCallback hiddenValueCallback = new HiddenValueCallback("clientScriptOutputData");

                Callback[] callbacks = new Callback[]{scriptAndSelfSubmitCallback,hiddenValueCallback};
                return send(callbacks).build();
            }

        } catch (Exception ex) {
            String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
            logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
            context.getStateFor(this).putShared(loggerPrefix + "Exception", ex.getMessage());
            context.getStateFor(this).putShared(loggerPrefix + "StackTrace", stackTrace);
            return Action.goTo("Error").build();
        }
    }

    public static String createClientSideScript(String url, boolean bdc, boolean debug) {

      String debugLine1 = "";
      String debugLine2 = "";
      String bdcLine = "";
      if(debug){
        debugLine1 = "console.log('PingOne Signals initialized successfully'); \n";
        debugLine2 = "console.error('PingOne SDK Init failed', e); \n";
      }
      if(!bdc){
        bdcLine = "behavioralDataCollection: false";
      }


      return  "var body=document.body; \n" +
              "var script = document.createElement('script');\n" +
              "script.type  = 'text/javascript';\n" +
              "script.src = '" + url + "';\n" +
              "script.setAttribute('defer','defer');\n" +
              "if (typeof window._pingOneSignals === 'function') { \n" +
              "   document.getElementById('loginButton_0').click()}else{ \n" +
              "   document.body.appendChild(script);\n" +
              "   Array.prototype.slice.call(document.getElementsByTagName('button')).forEach(function (e) {e.style.display = 'none'}) \n" +
              "function onPingOneSignalsReady(callback) { \n" +
              "   if (window['_pingOneSignalsReady']) { \n" +
              "        callback(); \n" +
              "    } else { \n" +
              "        document.addEventListener('PingOneSignalsReadyEvent', callback); \n" +
              "    }} \n" +
              "    onPingOneSignalsReady(function () { \n" +
              "    _pingOneSignals.init({ \n" + bdcLine +
              "    }).then(function () { \n" + debugLine1 +
              "        document.getElementById('loginButton_0').click()  \n" +
              "    }).catch(function (e) { \n" + debugLine2 +
              "    }); })};";
    }

    public static class OutcomeProvider implements StaticOutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(P1ProtectSignalInit.BUNDLE,
                    OutcomeProvider.class.getClassLoader());

            return ImmutableList.of(
                new Outcome("true", "true"),
                new Outcome("Error", "Error")
            );
        }
    }
}
