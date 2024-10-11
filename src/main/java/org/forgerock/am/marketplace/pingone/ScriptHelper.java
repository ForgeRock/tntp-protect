/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.marketplace.pingone;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.text.StrSubstitutor;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.json.JsonValue;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;



public class ScriptHelper {
	
    protected static final String sdkJsPathTemplate = "org/forgerock/am/marketplace/pingone/client.js";
    protected static final String sdkJsPathSigTemplate = "org/forgerock/am/marketplace/pingone/getSigs.js";

	static protected ScriptTextOutputCallback getScriptedCallback(String clientScript, JsonValue initValues) {
		String sdkJs = new StrSubstitutor(initValues.asMap()).replace(clientScript);
		return new ScriptTextOutputCallback(sdkJs);
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

}
