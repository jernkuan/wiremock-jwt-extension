package com.github.masonm;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.matching.MatchResult;
import com.github.tomakehurst.wiremock.matching.RequestMatcherExtension;
import com.github.tomakehurst.wiremock.matching.RequestPattern;

import java.util.Map;
import java.util.Objects;

import static com.github.tomakehurst.wiremock.matching.MatchResult.noMatch;
import static com.github.tomakehurst.wiremock.matching.MatchResult.exactMatch;

public class JwtMatcherExtension extends RequestMatcherExtension {
    public static final String NAME = "jwt-matcher";
    public static final String PARAM_NAME_QUERY_PARAMETER= "query-parameter";
    public static final String PARAM_NAME_HEADER_PARAMETER= "header-parameter";
    public static final String PARAM_NAME_PAYLOAD = "payload";
    public static final String PARAM_NAME_HEADER = "header";
    public static final String PARAM_NAME_REQUEST = "request";

    @Override
    public String getName() {
        return "jwt-matcher";
    }

    @Override
    public MatchResult match(Request request, Parameters parameters) {
        if (!parameters.containsKey(PARAM_NAME_PAYLOAD) && !parameters.containsKey(PARAM_NAME_HEADER)) {
            return noMatch();
        }

        if (parameters.containsKey(PARAM_NAME_QUERY_PARAMETER) && parameters.containsKey(PARAM_NAME_HEADER_PARAMETER)) {
            return noMatch();
        }

        if (parameters.containsKey(PARAM_NAME_REQUEST)) {
            Parameters requestParameters = Parameters.of(parameters.get(PARAM_NAME_REQUEST));
            RequestPattern requestPattern = requestParameters.as(RequestPattern.class);
            if (!requestPattern.match(request).isExactMatch()) {
                return noMatch();
            }
        }

        String authString = request.getHeader("Authorization");
        if (parameters.containsKey(PARAM_NAME_QUERY_PARAMETER))
        {
            authString = request.queryParameter(parameters.getString(PARAM_NAME_QUERY_PARAMETER)).firstValue();
        } else if (parameters.containsKey(PARAM_NAME_HEADER_PARAMETER)) { 
            authString = request.getHeader(parameters.getString(PARAM_NAME_HEADER_PARAMETER));
        }

        if (authString == null || authString.isEmpty()) {
            return noMatch();
        }

        Jwt token = Jwt.fromAuthHeader(authString);

        if (
            parameters.containsKey(PARAM_NAME_HEADER) &&
            !matchParams(token.getHeader(), parameters.get(PARAM_NAME_HEADER))
        ) {
            return noMatch();
        }

        if (
            parameters.containsKey(PARAM_NAME_PAYLOAD) &&
            !matchParams(token.getPayload(), parameters.get(PARAM_NAME_PAYLOAD))
        ) {
            return noMatch();
        }

        return exactMatch();
    }

    private boolean matchParams(JsonNode tokenValues, Object parameters) {
        Map<String, JsonNode> parameterMap = new ObjectMapper().convertValue(
            parameters,
            new TypeReference<Map<String, JsonNode>>() {}
        );
        for (Map.Entry<String, JsonNode> entry: parameterMap.entrySet()) {
            JsonNode tokenValue = tokenValues.path(entry.getKey());
            if (!Objects.equals(tokenValue, entry.getValue())) {
                return false;
            }
        }
        return true;
    }
}
