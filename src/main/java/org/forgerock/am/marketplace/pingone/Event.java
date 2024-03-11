/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */
package org.forgerock.am.marketplace.pingone;


import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Data Object for PingOne Evaluation API Request.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Event {
    private TargetResource targetResource;
    private String ip;
    private Sdk sdk;
    private Flow flow;
    private Session session;
    private User user;
    private String sharingType;
    private Browser browser;

    /**
     * Get the target app id.
     *
     * @return The App Id.
     */
    public TargetResource getTargetResource() {
        return targetResource;
    }

    /**
     * Set the target App ID.
     *
     * @param targetResource The App ID
     */
    public void setTargetResource(TargetResource targetResource) {
        this.targetResource = targetResource;
    }

    /**
     * Get the IP Address.
     *
     * @return The IP Address.
     */
    public String getIp() {
        return ip;
    }

    /**
     * Set the IP Address.
     * @param ip The ip address
     */
    public void setIp(String ip) {
        this.ip = ip;
    }

    /**
     * Get the SDK.
     *
     * @return The SDK
     */
    public Sdk getSdk() {
        return sdk;
    }

    /**
     * Set the SDK.
     *
     * @param sdk The SDK
     */
    public void setSdk(Sdk sdk) {
        this.sdk = sdk;
    }

    /**
     * Get the Flow.
     *
     * @return The Flow
     */
    public Flow getFlow() {
        return flow;
    }

    /**
     * Set the Flow.
     *
     * @param flow The Flow
     */
    public void setFlow(Flow flow) {
        this.flow = flow;
    }

    /**
     * Get the Session.
     *
     * @return The Session
     */
    public Session getSession() {
        return session;
    }

    /**
     * Set the Session.
     *
     * @param session The Session
     */
    public void setSession(Session session) {
        this.session = session;
    }

    /**
     * Get the User.
     *
     * @return The User
     */
    public User getUser() {
        return user;
    }

    /**
     * Set the User.
     *
     * @param user The User
     */
    public void setUser(User user) {
        this.user = user;
    }

    /**
     * Get the Sharing Type.
     *
     * @return The Sharing Type
     */
    public String getSharingType() {
        return sharingType;
    }

    /**
     * Set the Sharing type.
     *
     * @param sharingType The Sharing Type
     */
    public void setSharingType(String sharingType) {
        this.sharingType = sharingType;
    }

    /**
     * Get the Browser.
     *
     * @return The Browser.
     */
    public Browser getBrowser() {
        return browser;
    }

    /**
     * Set the Browser.
     *
     * @param browser The Browser.
     */
    public void setBrowser(Browser browser) {
        this.browser = browser;
    }

    /**
     * Flow data object.
     */
    public static class Flow {

        private String type;

        /**
         * Flow Constructor.
         *
         * @param type The flow type
         */
        public Flow(String type) {
            this.type = type;
        }

        /**
         * Get the flow type.
         *
         * @return The flow type
         */
        public String getType() {
            return type;
        }

    }

    /**
     * Group data object.
     */
    public static class Group {
        /**
         * Get the group name.
         *
         * @return The group name
         */
        public String getName() {
            return name;
        }

        /**
         * Set the group name.
         *
         * @param name The group name
         */
        public void setName(String name) {
            this.name = name;
        }

        private String name;
    }

    /**
     * Risk Policy Set data object.
     */
    public static class RiskPolicySet {
        private String id;

        /**
         * Set the policy set id.
         *
         * @param id The policy set id
         */
        public RiskPolicySet(String id) {
            this.id = id;
        }

        /**
         * Get the policy set id.
         *
         * @return The policy set id.
         */
        public String getId() {
            return id;
        }
    }

    /**
     * The Root data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Root {
        private Event event;
        private RiskPolicySet riskPolicySet;

        /**
         * Get the event.
         *
         * @return The Event.
         */
        public Event getEvent() {
            return event;
        }

        /**
         * Set the event.
         *
         * @param event The event.
         */
        public void setEvent(Event event) {
            this.event = event;
        }

        /**
         * Get the risk policy set.
         *
         * @return The risk policy set
         */
        public RiskPolicySet getRiskPolicySet() {
            return riskPolicySet;
        }

        /**
         * Set the risk policy set.
         *
         * @param riskPolicySet The risk policy set.
         */
        public void setRiskPolicySet(RiskPolicySet riskPolicySet) {
            this.riskPolicySet = riskPolicySet;
        }
    }


    /**
     * The SDK data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Sdk {
        private Signals signals;

        /**
         * Set the signals.
         *
         * @param signals The signals
         */
        public Sdk(Signals signals) {
            this.signals = signals;
        }

        /**
         * Get the signals.
         *
         * @return the signals.
         */
        public Signals getSignals() {
            return signals;
        }

    }

    /**
     * The Session data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Session {
        private String id;

        /**
         * Get the session id.
         *
         * @return The Session id.
         */
        public String getId() {
            return id;
        }

        /**
         * Set the session id.
         *
         * @param id The session id.
         */
        public void setId(String id) {
            this.id = id;
        }
    }

    /**
     * The Signal data object.
     */
    public static class Signals {
        private String data;

        /**
         * Set the signal data.
         *
         * @param data The signal data
         */
        public Signals(String data) {
            this.data = data;
        }

        /**
         * Get the signal data.
         *
         * @return the signal data
         */
        public String getData() {
            return data;
        }
    }

    /**
     * The target resource data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class TargetResource {

        /**
         * Constructor with target resource id.
         *
         * @param id The target resource id
         */
        public TargetResource(String id) {
            this.id = id;
        }

        private String id;

        /**
         * Get the target resource id.
         *
         * @return the target resource id.
         */
        public String getId() {
            return id;
        }
    }

    /**
     * The user data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class User {
        private String id;

        private String name;
        private String type;

        /**
         * Constructor for User data object.
         *
         * @param id The user id
         * @param name The user name
         * @param type The user type
         */
        public User(String id, String name, String type) {
            this.id = id;
            this.name = name;
            this.type = type;
        }

        /**
         * Get the user id.
         *
         * @return The user id
         */
        public String getId() {
            return id;
        }

        /**
         * Get the username.
         *
         * @return the username
         */
        public String getName() {
            return name;
        }

        /**
         * Get the user type.
         *
         * @return The user type.
         */
        public String getType() {
            return type;
        }

    }

    /**
     * The browser data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Browser {
        private String userAgent;

        /**
         * Constructor with user agent.
         *
         * @param userAgent The user agent.
         */
        public Browser(String userAgent) {
            this.userAgent = userAgent;
        }

        /**
         * Get user agent.
         *
         * @return The user agent.
         */
        public String getUserAgent() {
            return userAgent;
        }
    }
}




