/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.am.marketplace.pingone;

import java.util.LinkedHashMap;
import java.util.Map;

import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmLookup;
import org.forgerock.openam.core.realms.Realms;
import org.forgerock.openam.sm.annotations.subconfigs.Multiple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import com.sun.identity.shared.Constants;
import com.sun.identity.sm.ChoiceValues;

/**
 * Provide choice for PingOne Worker.
 */
public class PingOneWorkerServiceChoiceValues extends ChoiceValues {

    private static final Logger LOGGER = LoggerFactory.getLogger(PingOneWorkerServiceChoiceValues.class);

    private RealmLookup realmLookup;
    private final PingOneWorkerService pingOneWorkerService;

    @Inject
    PingOneWorkerServiceChoiceValues(RealmLookup realmLookup, PingOneWorkerService pingOneWorkerService) {
        this.realmLookup = realmLookup;
        this.pingOneWorkerService = pingOneWorkerService;
    }

    @Override
    public Map<String, String> getChoiceValues() {
        return getChoiceValues(Map.of());
    }

    @Override
    public Map<String, String> getChoiceValues(Map<String, Object> envParams) {
        Realm realm = Realms.root();
        Map<String, String> result = new LinkedHashMap<>();

        try {
            if (envParams != null && envParams.containsKey(Constants.ORGANIZATION_NAME)) {
                realm = realmLookup.lookup((String) envParams.get(Constants.ORGANIZATION_NAME));
            }

            Multiple<PingOneWorkerConfig.Worker> workers = pingOneWorkerService.getWorkers(realm);
            workers.idSet().forEach(s -> result.put(s, s));
        } catch (Exception e) {
            LOGGER.error("Error getting the list of available PingOne Worker for the realm {}", realm, e);
        }

        return result;
    }
}