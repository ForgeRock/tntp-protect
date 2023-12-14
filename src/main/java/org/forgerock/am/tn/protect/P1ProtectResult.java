package org.forgerock.am.tn.protect;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.StaticOutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;


 @Node.Metadata(outcomeProvider = P1ProtectResult.OutcomeProvider.class,
         configClass = P1ProtectResult.Config.class, tags = {"marketplace", "trustnetwork"})
 public class P1ProtectResult extends AbstractDecisionNode {


   private final Logger logger = LoggerFactory.getLogger(P1ProtectResult.class);
   private String loggerPrefix = "[P1ProtectResult]" + P1ProtectSignalInitPlugin.logAppender;

   private final Config config;
   private static final String BUNDLE = P1ProtectResult.class.getName();
   public enum JourneyResult { SUCCESS, FAILURE }

    private static final String SUCCESS = "TRUE";
    private static final String ERROR = "ERROR";

   public String getJourneyResult(JourneyResult result) {
       if (result == JourneyResult.SUCCESS) return "SUCCESS";
       else return "FAILED";
   }

    /**
     * Configuration for the node.
     */
    public interface Config {

         @Attribute(order = 100)
            default JourneyResult journeyResult() {
                return JourneyResult.SUCCESS;
         }

         @Attribute(order = 200)
         default boolean apiResponse() {
           return false;
         }


    }


    /**
     * This node will send the result to the ping protect to let it know if it was a protect/failure
     */

    @Inject
    public P1ProtectResult(@Assisted Config config) throws NodeProcessException {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        try {
            String p1accessToken;
            NodeState ns = context.getStateFor(this);
            String p1RiskEvalId = ns.get("p1RiskEvalId").asString();
            boolean useShared=false;
            p1accessToken = ns.get("p1accessToken").asString();

            if(p1accessToken==null || p1accessToken.equals("")){
                p1accessToken = ns.get("p1accessToken").asString();
                useShared=true;
            }
            String p1riskEndpoint = ns.get("p1riskEndpoint").asString();
            p1riskEndpoint = p1riskEndpoint + "/" + p1RiskEvalId + "/event";

            if(useShared) {
                ns.putShared("p1accessToken", "");
            }
            ns.putShared("p1riskEndpoint", "");

            boolean bResult;
            if(config.journeyResult().toString().equals("SUCCESS")){
                bResult=true;
            } else {
                bResult=false;
            }

            String apiResult = sendTxResult(p1riskEndpoint,p1accessToken,p1RiskEvalId,bResult);
            if(apiResult.substring(0,4).equals("error") || config.apiResponse()){
                ns.putShared("p1ResultApiResult", apiResult);
            }


            return Action.goTo(SUCCESS).build();
        } catch(Exception ex) {
            String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
            logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
            context.getStateFor(this).putShared(loggerPrefix + "Exception", ex.getMessage());
            context.getStateFor(this).putShared(loggerPrefix + "StackTrace", stackTrace);
            return Action.goTo(ERROR).build();
        }
    }

    //Send the success/fail result to ping protect
    private String sendTxResult(String endpoint, String accessToken, String p1RiskEvalId, boolean result) {
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

        conn.setRequestMethod("PUT");
        String body;
        if(result){
          body = "{\"completionStatus\": \"SUCCESS\"}";
        } else {
          body = "{\"completionStatus\": \"FAILED\"}";
        }
        OutputStream os = conn.getOutputStream();
        os.write(body.getBytes("UTF-8"));
        os.close();

        if(conn.getResponseCode()==200){
          BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
          String inputLine;
          while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
          }
          in.close();

          return response.toString();

        } else {
          return "error:" + Integer.toString(conn.getResponseCode());
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


    public static class OutcomeProvider implements StaticOutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(P1ProtectResult.BUNDLE,
                    OutcomeProvider.class.getClassLoader());

            return ImmutableList.of(
                new Outcome(SUCCESS, bundle.getString("SuccessOutcome")),
                new Outcome(ERROR, bundle.getString("ErrorOutcome"))
            );
        }
    }

}
