package org.forgerock.am.marketplace.pingone;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.text.StrSubstitutor;
import org.forgerock.openam.auth.node.api.NodeProcessException;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;



public class ScriptHelper {
	
    private static final String sdkJsPathTemplate = "org/forgerock/am/marketplace/pingone/client.js";

	static protected ScriptTextOutputCallback getScriptedCallback(String clientScript, String environmentId, String consoleLogEnabled, String deviceAttributesToIgnore, String customHost, String lazyMetadata, String behavioralDataCollection, String deviceKeyRsyncIntervals, String enableTrust, String disableTags, String disableHub) {
		Map<String, String> sdkConfigMap = new HashMap<>();
		sdkConfigMap.put("subclientID", environmentId);
		sdkConfigMap.put("subchainNamespace", consoleLogEnabled);
		sdkConfigMap.put("subrpcTarget", deviceAttributesToIgnore);
		sdkConfigMap.put("subchainId", customHost);
		sdkConfigMap.put("subdisplayName", lazyMetadata);
		sdkConfigMap.put("behavioralDataCollection", behavioralDataCollection);
		sdkConfigMap.put("subticker", deviceKeyRsyncIntervals);
		sdkConfigMap.put("subtickerName", enableTrust);
		sdkConfigMap.put("subweb3AuthNetwork", disableTags);
		sdkConfigMap.put("subverifier", disableHub);
		String sdkJs = new StrSubstitutor(sdkConfigMap).replace(clientScript);
		ScriptTextOutputCallback callback = new ScriptTextOutputCallback(sdkJs);
		return callback;
	}

	static protected String readJS() throws NodeProcessException {
		URL resource = Resources.getResource(sdkJsPathTemplate);
		try {
			return Resources.toString(resource, Charsets.UTF_8);
		} catch (IOException ex) {
			throw new NodeProcessException(ex);
		}
	}

}
