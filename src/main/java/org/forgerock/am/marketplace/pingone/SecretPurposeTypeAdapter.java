/*
 * Copyright 2023 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.am.marketplace.pingone;

import static java.lang.String.format;
import static org.forgerock.openam.sm.annotations.adapters.AdapterUtils.firstGenericArg;

import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.annotations.adapters.AttributeSchemaBuilder;
import org.forgerock.openam.sm.annotations.adapters.TypeAdapter;
import org.forgerock.openam.sm.annotations.model.AttributeSyntax;
import org.forgerock.openam.sm.annotations.model.AttributeType;
import org.forgerock.openam.sm.validation.SecretIdValidator;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.Secret;

import com.sun.identity.sm.ServiceAttributeValidator;

import io.vavr.control.Either;

/**
 * {@link TypeAdapter} for secret {@link Purpose} attributes.
 */
public class SecretPurposeTypeAdapter implements TypeAdapter<Purpose<?>> {

    private static final int KEEP_TRAILING_EMPTY_STRINGS = -1;

    @Override
    public boolean isApplicable(Type type) {
        if (!(type instanceof ParameterizedType)) {
            return false;
        }
        ParameterizedType parameterizedType = (ParameterizedType) type;
        Type rawType = parameterizedType.getRawType();
        return rawType.equals(Purpose.class);
    }

    @Override
    public AttributeSyntax getSyntax(Type type) {
        return AttributeSyntax.STRING;
    }

    @Override
    public AttributeType getType(Type type) {
        return AttributeType.SINGLE;
    }

    @Override
    public void augmentAttributeSchema(Type type, AttributeSchemaBuilder attributeSchemaBuilder, Optional<Annotation> annotation) {
        // no specific attribute for secret type adapter
    }

    @Override
    public Either<IllegalStateException, Purpose<?>> convertFromStrings(Type type, Optional<Realm> realm, Set<String> values, Optional<Annotation> annotation) {
        String secretId;
        Optional<String> value = values.stream().findFirst();
        if (value.isEmpty()) {
            // the attribute must be either mandatory or an Optional.
            return Either.left(new IllegalStateException("Label cannot be empty"));
        }
        if (annotation.isPresent() && annotation.get().annotationType().equals(SecretPurpose.class)) {
            secretId = format(((SecretPurpose) annotation.get()).value(), value.get());
        } else {
            secretId = value.get();
        }
        Type secretType = firstGenericArg(type);
        Purpose<? extends Secret> purpose;
        try {
            purpose = Purpose.purpose(secretId, (Class<? extends Secret>) secretType);
        } catch (IllegalArgumentException e) {
            return Either.left(new IllegalStateException("Label contains illegal characters"));
        }
        return Either.right(purpose);
    }

    @Override
    public Set<String> convertToStrings(Type type, Purpose<?> value, Optional<Annotation> annotation) {
        if (annotation.isPresent() && annotation.get().annotationType().equals(SecretPurpose.class)) {
            String template = ((SecretPurpose) annotation.get()).value();
            Pattern pattern = Pattern.compile(Arrays.stream(template.split("%s", KEEP_TRAILING_EMPTY_STRINGS))
                                                      .map(Pattern::quote)
                                                      .collect(Collectors.joining("(?<label>.*)")));
            Matcher matcher = pattern.matcher(value.getLabel());
            if (matcher.matches()) {
                return Set.of(matcher.group("label"));
            }
        }
        return Set.of(value.getLabel());
    }

    
    public Set<Class<? extends ServiceAttributeValidator>> getValidators(Type type, Optional<Annotation> annotation) {
        return Set.of(SecretIdValidator.class);
    }
}