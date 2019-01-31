package io.baardl.jwt.validator.utils;

import org.constretto.ConstrettoBuilder;
import org.constretto.ConstrettoConfiguration;
import org.constretto.model.Resource;

import java.util.Map;

public final class Configuration {
    private static final ConstrettoConfiguration configuration = new ConstrettoBuilder()
            .createPropertiesStore()
            .addResource(Resource.create("classpath:jwtValidation.properties"))
            .addResource(Resource.create("file:./jwtValidation_override.properties"))
            .done()
            .getConfiguration();

    private Configuration() {
    }

    public static Map getMap(String key) {
        return configuration.evaluateToMap(String.class, String.class, key);
    }

    public static String getString(String key) {
        return configuration.evaluateToString(key);
    }

    public static Integer getInt(String key) {
        return configuration.evaluateToInt(key);
    }

    public static Integer getInt(String key, int defaultValue) {
        return configuration.evaluateTo(key, defaultValue);
    }

    public static boolean getBoolean(String key) {
        return configuration.evaluateToBoolean(key);
    }
}
