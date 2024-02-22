/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.am.marketplace.pingone;


import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.annotations.adapters.AdapterUtils;
import org.forgerock.openam.sm.annotations.adapters.AttributeSchemaBuilder;
import org.forgerock.openam.sm.annotations.adapters.TypeAdapter;
import org.forgerock.openam.sm.annotations.model.AttributeSyntax;
import org.forgerock.openam.sm.annotations.model.AttributeType;
import org.forgerock.openam.sm.annotations.model.UiType;

import com.google.inject.Inject;

import io.vavr.control.Either;

/**
 * Type adapter for {@link PingOneWorkerConfig.Worker}. The worker is converted to/from a name.
 */
public final class PingOneWorkerTypeAdapter implements TypeAdapter<PingOneWorkerConfig.Worker> {

    private final PingOneWorkerService pingoneWorkerService;

    /**
     * Default constructor for handling choices on the UI for the PingOneProtect Node.
     * @param pingoneWorkerService Service for tree data management.
     */
    @Inject
    public PingOneWorkerTypeAdapter(PingOneWorkerService pingoneWorkerService) {
        this.pingoneWorkerService = pingoneWorkerService;
    }

    @Override
    public boolean isApplicable(Type type) {
        return type.equals(PingOneWorkerConfig.Worker.class);
    }

    @Override
    public AttributeSyntax getSyntax(Type type) {
        return AttributeSyntax.STRING;
    }

    @Override
    public AttributeType getType(Type type) {
        return AttributeType.SINGLE_CHOICE;
    }

    @Override
    public Optional<UiType> getUiType(Type type) {
        return Optional.of(UiType.SCRIPT_SELECT);
    }

    @Override
    public void augmentAttributeSchema(Type type, AttributeSchemaBuilder attributeSchemaBuilder,
            Optional<Annotation> annotation) {
        attributeSchemaBuilder
                .addDynamicChoiceValues(PingOneWorkerServiceChoiceValues.class);
    }

    @Override
    public Set<String> convertToStrings(Type type, PingOneWorkerConfig.Worker value, Optional<Annotation> annotation) {
        return Collections.singleton(value.id());
    }

    @Override
    public Either<IllegalStateException, PingOneWorkerConfig.Worker> convertFromStrings(Type type,
        Optional<Realm> realm, Set<String> value, Optional<Annotation> annotation) {
        if (realm.isEmpty()) {
            throw new IllegalStateException("PingOne Worker can only be used in realms");
        }
        return AdapterUtils.validateSingleValue(value).map(v -> pingoneWorkerService.getWorker(realm.get(), v)
                .orElseThrow(() -> new IllegalStateException("PingOne Worker could not be found")));
    }
}