package org.forgerock.am.tn.protect;

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;

@Node.Metadata(outcomeProvider = P1ProtectGetData.P1ProtectGetDataOutcomeProvider.class, configClass = P1ProtectGetData.Config.class)
public class P1ProtectGetData implements Node {

	private final Logger logger = LoggerFactory.getLogger(P1ProtectGetData.class);
	private String loggerPrefix = "[P1ProtectGetData]" + P1ProtectSignalInitPlugin.logAppender;

	private final Config config;
	private static final String BUNDLE = P1ProtectGetData.class.getName();

	/**
	 * Configuration for the node.
	 */
	public enum UserType {
		EXTERNAL, PING_ONE
	}

	public enum ProtectRegion {
		EU, US, APAC, CANADA
	}

	public enum FlowType {
		AUTHENTICATION, AUTHORIZATION, REGISTRATION
	}

	public String getUserType(UserType userType) {
		if (userType == UserType.EXTERNAL)
			return "EXTERNAL";
		else
			return "PING_ONE";
	}

	public String getProtectRegion(ProtectRegion protectRegion) {
		if (protectRegion == ProtectRegion.EU) {
			return "eu";
		} else if (protectRegion == ProtectRegion.APAC) {
			return "asia";
		} else if (protectRegion == ProtectRegion.CANADA) {
			return "ca";
		} else
			return "com";
	}

	public String getFlowType(FlowType flowType) {
		if (flowType == FlowType.AUTHENTICATION) {
			return "AUTHENTICATION";
		} else if (flowType == FlowType.AUTHORIZATION) {
			return "AUTHORIZATION";
		} else
			return "REGISTRATION";
	}

	public static String signalsData;
	public static String passwdMSB = "";
	public static String lowRisk = "LOW";
	public static String mediumRisk = "MEDIUM";
	public static String highRisk = "HIGH";
	public static String botRisk = "BOT_MITIGATION";

	public interface Config {

		@Attribute(order = 60)
		default UserType userType() {
			return UserType.EXTERNAL;
		}

		@Attribute(order = 70)
		default FlowType flowType() {
			return FlowType.AUTHENTICATION;
		}

		@Attribute(order = 80)
		default String tokenUrl() {
			return "";
		}

		@Attribute(order = 100)
		default String clientId() {
			return "";
		}

		@Attribute(order = 120)
		@Password
		char[] clientSecret();

		@Attribute(order = 160)
		default ProtectRegion protectRegion() {
			return ProtectRegion.EU;
		}

		@Attribute(order = 180)
		default String envId() {
			return "";
		}

		@Attribute(order = 200)
		default String policyId() {
			return "";
		}

		@Attribute(order = 220)
		default boolean evalPasswd() {
			return false;
		}

		@Attribute(order = 260)
		List<String> advice();

		/*
		default boolean botResult() {
			return true;
		}*/

		@Attribute(order = 280)
		default boolean apiResponse() {
			return true;
		}

		@Attribute(order = 320)
		default boolean dbg() {
			return false;
		}

	}

	/**
	 * Create the node using Guice injection. Just-in-time bindings can be used to
	 * obtain instances of other classes from the plugin.
	 *
	 * @param config The service config.
	 * @param realm  The realm the node is in.
	 * @throws NodeProcessException If the configuration was not valid.
	 */

	@Inject
	public P1ProtectGetData(@Assisted Config config) throws NodeProcessException {
		this.config = config;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {

		try {
			if (config.dbg()) {
				logger.debug(loggerPrefix + "Node started");
			}

			Optional<String> result = context.getCallback(HiddenValueCallback.class).map(HiddenValueCallback::getValue)
					.filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput));
			boolean bdc = false;
			NodeState ns = context.getStateFor(this);

			if (ns.get("PingOneProtectInit").asString() != null) {
				bdc = true;
			}
			String userAgent = context.request.headers.get("user-agent").toArray()[0].toString();

			List<String> xfheader = context.request.headers.get("X-FORWARDED-FOR");
			String ipAddress = "127.0.0.1";
			if (xfheader != null && xfheader.size() > 0)
				ipAddress = xfheader.toArray()[0].toString();
			String userName = ns.get(USERNAME).asString();

			String riskEndpoint = "https://api.pingone." + getProtectRegion(config.protectRegion()) + "/v1/environments/" + config.envId() + "/riskEvaluations";

			String endpoint = config.tokenUrl() + config.envId() + "/as/token";
			String client_secret = new String(config.clientSecret());
			String userType = config.userType().toString();
			String resourceId = "endUserUI";
			String policyId = config.policyId();
			String flowType = config.flowType().toString();

			if (config.evalPasswd()) {
				if (result.isEmpty() || !bdc) {
					String userPassword = ns.get(PASSWORD).asString();
					if (userPassword != null && !userPassword.equals("")) {
						MessageDigest md = MessageDigest.getInstance("SHA-256");
						byte[] hash = md.digest(userPassword.getBytes(StandardCharsets.UTF_8));
						String userPasswordHash = bytesToHex(hash);
						passwdMSB = userPasswordHash.substring(0, 32);
						ns.putShared("passwdMSB",passwdMSB);
					}
				}
				else {
					if(ns.isDefined("passwdMSB")) {
						passwdMSB = ns.get("passwdMSB").asString();
					}
				}
			}
			String accessToken = "";
			if(!ns.isDefined("p1accessToken")) {
				accessToken = getAccessToken(endpoint, config.clientId(), client_secret);
				if (Objects.equals(accessToken, "error")) {
					logger.debug(loggerPrefix + "Failed to obtain PingOne service access token");
					if (config.dbg()) {
						ns.putShared("PingOneProtectTokenError", "Failed to obtain access token for PingOne Protect");
					}
					return Action.goTo("error").build();
				}
				//ns.putShared("p1accessToken", accessToken);
				ns.putTransient("p1accessToken", accessToken);
			}
			else {
				accessToken = ns.get("p1accessToken").asString();
			}
			ns.putShared("p1riskEndpoint", riskEndpoint);

			if (bdc) {
				if (result.isPresent()) {
					signalsData = result.get();
					if (config.dbg()) {
						ns.putShared("p1ProtectSignalsData", signalsData);
					}
					String signals = signalsData;
					String riskEvalRequestBody = createRiskEvaluationBody(policyId, userName, resourceId, signals,
							userType, ipAddress, flowType, userAgent, passwdMSB);
					String riskEval = createRiskEvaluation(accessToken, riskEndpoint, riskEvalRequestBody);

					if (Objects.equals(riskEval.substring(0, 4),"error")) {
						ns.putShared("p1riskEvalError", riskEval);
						return Action.goTo("error").build();
					}
					if (config.apiResponse()) {
						ns.putShared("p1riskEval", riskEval);
					}
					String riskLevel = getRiskLevel(riskEval, config.advice());
					String riskEvalId = getRiskEvaluationId(riskEval);
					String riskScore = getRiskScore(riskEval);

					ns.putShared("p1RiskEvalId", riskEvalId);
					ns.putShared("p1RiskLevel", riskLevel);
					ns.putShared("p1RiskScore", riskScore);

					return Action.goTo(riskLevel).build();

				} else {
					if (config.dbg()) {
						logger.debug(loggerPrefix + "Sending callbacks");
					}
					String clientSideScriptExecutorFunction = createClientSideScript(config.dbg());
					ScriptTextOutputCallback scriptAndSelfSubmitCallback = new ScriptTextOutputCallback(
							clientSideScriptExecutorFunction);
					HiddenValueCallback hiddenValueCallback = new HiddenValueCallback("clientScriptOutputData");
					Callback[] callbacks = new Callback[] { scriptAndSelfSubmitCallback, hiddenValueCallback };
					return send(callbacks).build();
				}
			} else {
				/* Not collecting signals data */
				String riskEvalRequestBody = createRiskEvaluationBody(policyId, userName, resourceId, "", userType,
						ipAddress, flowType, userAgent, passwdMSB);
				String riskEval = createRiskEvaluation(accessToken, riskEndpoint, riskEvalRequestBody);
				if (Objects.equals(riskEval.substring(0, 4),"error")) {
					ns.putShared("p1riskEvalError", riskEval);
					return Action.goTo("error").build();
				}
				if (config.apiResponse()) {
					ns.putShared("p1riskEval", riskEval);
				}
				String riskLevel = getRiskLevel(riskEval, config.advice());
				String riskEvalId = getRiskEvaluationId(riskEval);
				String riskScore = getRiskScore(riskEval);

				ns.putShared("p1RiskEvalId", riskEvalId);
				ns.putShared("p1RiskLevel", riskLevel);
				ns.putShared("p1RiskScore", riskScore);

				return Action.goTo(riskLevel).build();
			}
		} catch (Exception ex) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
			logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
			context.getStateFor(this).putShared(loggerPrefix + "Exception", ex.getMessage());
			context.getStateFor(this).putShared(loggerPrefix + "StackTrace", stackTrace);
			return Action.goTo("error").build();
		}
	}

	public static String bytesToHex(byte[] hash) {
		StringBuilder hexString = new StringBuilder(2 * hash.length);
		for (int i = 0; i < hash.length; i++) {
			String hex = Integer.toHexString(0xff & hash[i]);
			if (hex.length() == 1) {
				hexString.append('0');
			}
			hexString.append(hex);
		}
		return hexString.toString();
	}

	public static String getRiskLevel(String riskEval, List<String> advices) {
		JSONObject obj = new JSONObject(riskEval);
		String riskLevel = obj.getJSONObject("result").getString("level");

		if (!advices.isEmpty()) {
			if (obj.getJSONObject("result").has("recommendedAction")) {
				String recommendedAction = obj.getJSONObject("result").getString("recommendedAction");

				boolean matchedOutcome = false;
				for(int i=0; i<advices.size(); i++) {
					if(Objects.equals(recommendedAction, advices.get(i))){
						matchedOutcome = true;
						i = advices.size();
					}
				}
				if(matchedOutcome) {
					riskLevel = recommendedAction;
				}
			}
		}
		return riskLevel;
	}

	public static String getRiskEvaluationId(String riskEval) {
		JSONObject obj = new JSONObject(riskEval);
        return obj.getString("id");
	}

	public static String getRiskScore(String riskEval) {
		JSONObject obj = new JSONObject(riskEval);
        return obj.getJSONObject("result").get("score").toString();
	}

	public static String createRiskEvaluation(String accessToken, String endpoint, String body) {
		StringBuffer response = new StringBuffer();
		HttpURLConnection conn = null;
		try {
			URL url = new URL(endpoint);
			conn = (HttpURLConnection) url.openConnection();
			conn.setConnectTimeout(4000);
			conn.setDoOutput(true);
			conn.setDoInput(true);
			conn.setRequestProperty("Content-Type", "application/json");
			conn.setRequestProperty("Authorization", "Bearer " + accessToken);
			conn.setRequestMethod("POST");

			OutputStream os = conn.getOutputStream();
			os.write(body.getBytes("UTF-8"));
			os.close();

			if (conn.getResponseCode() == 201) {
				BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
				String inputLine;
				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine);
				}
				in.close();
				return response.toString();
			} else {
				return "error:" + response.toString();
			}
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		finally {
			if(conn!=null) {
				conn.disconnect();
			}
		}
		return "error";
	}

	public static String getAccessToken(String endpoint, String client_id, String client_secret) {
		HttpURLConnection conn = null;
		try {
			URL url = new URL(endpoint);
			conn = (HttpURLConnection) url.openConnection();
			conn.setConnectTimeout(4000);
			conn.setDoOutput(true);
			conn.setDoInput(true);
			conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			conn.setRequestMethod("POST");
			String body = "grant_type=client_credentials&client_id=" + client_id + "&client_secret=" + client_secret
					+ "&scope=default";
			OutputStream os = conn.getOutputStream();
			os.write(body.getBytes("UTF-8"));
			os.close();

			if (conn.getResponseCode() == 200) {
				BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
				String inputLine;
				StringBuffer response = new StringBuffer();
				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine);
				}
				in.close();
				JSONObject obj = new JSONObject(response.toString());
                return obj.getString("access_token");
			} else {
				return "error";
			}
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		finally {
			if(conn!=null) {
				conn.disconnect();
			}
		}
		return "error";
	}

	public static String createRiskEvaluationBody(String policyId, String userName, String resourceId, String signals,
			String userType, String ipAddress, String flowType, String userAgent, String userPassword) {
		String body = "{\"event\": {\"targetResource\": {\"id\":\"" + resourceId + "\",\"name\":\"" + resourceId
				+ "\"},";
		body = body + "\"ip\":\"" + ipAddress + "\",";
		if (!Objects.equals(signals, "") && signals != null) {
			body = body + "\"sdk\": {\"signals\": {\"data\":\"" + signals + "\"}},";
		}
		body = body + "\"flow\": {\"type\":\"" + flowType + "\"},";
		body = body + "\"user\": {\"id\":\"" + userName + "\",\"name\":\"" + userName + "\",\"type\":\"" + userType
				+ "\"";
		if (userPassword != null && !userPassword.equals("")) {
			body = body + ",\"password\": { \"hash\": { \"algorithm\": \"SHA_256\", \"value\": \"" + userPassword
					+ "\"}}},";
		} else {
			body = body + "},";
		}
		body = body + "\"sharingType\": \"SHARED\",\"browser\": {\"userAgent\":\"" + userAgent + "\"}}";
		if (!Objects.equals(policyId, "") && policyId != null) {
			body = body + ",\"riskPolicySet\": {\"id\":\"" + policyId + "\"}}";
		} else {
			body = body + "}";
		}
		return body;
	}

	public static String createClientSideScript(boolean debug) {

		String debugLine1 = "";
		String debugLine2 = "";
		if (debug) {
			debugLine1 = "console.log('get data completed: ' + result) \n";
			debugLine2 = "console.error('getData Error!', e);\n";
		}

		return "      _pingOneSignals.getData()  \n" + "       .then(function (result) { setTimeout(function() { \n" + debugLine1
				+ "           document.getElementById('clientScriptOutputData').value=result   \n"
				+ "           document.getElementById('loginButton_0').click(); },500)  \n"
				+ "       }).catch(function (e) {  \n" + debugLine2 + "  });";
	}

	public static class P1ProtectGetDataOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

			List<Outcome> results = new ArrayList<>();
			results.add(new Outcome(lowRisk, "low"));
			results.add(new Outcome(mediumRisk, "medium"));
			results.add(new Outcome(highRisk, "high"));
			results.add(new Outcome("error", "error"));

			for (String s : nodeAttributes.get("advice").required().asList(String.class)) {
                results.add(new Outcome(s, s));
			}
			return Collections.unmodifiableList(results);
		}
	}
}
