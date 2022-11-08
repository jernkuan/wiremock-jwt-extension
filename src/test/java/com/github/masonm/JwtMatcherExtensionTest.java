package com.github.masonm;

import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.matching.MockRequest;
import com.google.common.collect.ImmutableMap;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.matching.MockRequest.mockRequest;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class JwtMatcherExtensionTest {
    private static final TestAuthHeader TEST_AUTH_HEADER = new TestAuthHeader(
        "{ \"test_header\": \"header_value\" }",
        "{ \"test_payload\": \"payload_value\" }"
    );
    private static final Parameters JWT_PAYLOAD_PARAMETER = Parameters.one(
        JwtMatcherExtension.PARAM_NAME_PAYLOAD,
        ImmutableMap.of("test_payload", "payload_value")
    );
    private static final Parameters JWT_HEADER_PARAMETER = Parameters.one(
        JwtMatcherExtension.PARAM_NAME_HEADER,
        ImmutableMap.of("test_header", "header_value")
    );
    private static final Parameters HEADER_PARAMETER = Parameters.one(
        JwtMatcherExtension.PARAM_NAME_HEADER_PARAMETER,
        "x-key"
    );
    private static final Parameters QUERY_PARAMETER = Parameters.one(
        JwtMatcherExtension.PARAM_NAME_QUERY_PARAMETER,
        "token"
    );
    private static final Parameters BOTH_PARAMETERS = new Parameters() {{
        putAll(JWT_PAYLOAD_PARAMETER);
        putAll(JWT_HEADER_PARAMETER);
    }};

    @Test
    public void noMatchWithMissingRequiredParameters() {
        assertFalse(isExactMatch(mockRequest(), Parameters.empty()));

        Parameters invalidParameters = Parameters.one("test_header", "test_payload");
        assertFalse(isExactMatch(mockRequest(), invalidParameters));
    }

    @Test
    public void noMatchWithBothHeaderAndQueryParameters() {
        assertFalse(isExactMatch(mockRequest(), new Parameters() {
            {
                putAll(HEADER_PARAMETER);
                putAll(QUERY_PARAMETER);

            }
        }));
    }

    @Test
    public void withValidParametersAndMatchingRequest() {
        final MockRequest request = mockRequest().header("Authorization", TEST_AUTH_HEADER.toString());

        assertTrue(isExactMatch(request, JWT_PAYLOAD_PARAMETER));
        assertTrue(isExactMatch(request, JWT_HEADER_PARAMETER));
        assertTrue(isExactMatch(request, BOTH_PARAMETERS));
    }

    @Test
    public void withValidParametersAndRequestWithoutAuthorization() {
        final MockRequest request = mockRequest();
        assertFalse(isExactMatch(request, JWT_PAYLOAD_PARAMETER));
        assertFalse(isExactMatch(request, JWT_HEADER_PARAMETER));
        assertFalse(isExactMatch(request, BOTH_PARAMETERS));
    }

    @Test
    public void withValidParametersAndRequestWithInvalidAuthorization() {
        final MockRequest request = mockRequest().header("Authorization", "Bearer f00");
        assertFalse(isExactMatch(request, JWT_PAYLOAD_PARAMETER));
        assertFalse(isExactMatch(request, JWT_HEADER_PARAMETER));
        assertFalse(isExactMatch(request, BOTH_PARAMETERS));
    }

    @Test
    public void withValidParametersAndNonMatchingRequest() {
        final MockRequest requestOnlyMatchingPayload = mockRequest()
            .header("Authorization", new TestAuthHeader(
                 "{}",
                 "{ \"test_payload\": \"payload_value\" }"
            ).toString());
        assertFalse(isExactMatch(requestOnlyMatchingPayload, JWT_HEADER_PARAMETER));
        assertFalse(isExactMatch(requestOnlyMatchingPayload, BOTH_PARAMETERS));

        final MockRequest requestOnlyMatchingHeader = mockRequest()
            .header("Authorization", new TestAuthHeader(
                "{ \"test_header\": \"header_value\" }",
                "{}"
            ).toString());
        assertFalse(isExactMatch(requestOnlyMatchingHeader, JWT_PAYLOAD_PARAMETER));
        assertFalse(isExactMatch(requestOnlyMatchingHeader, BOTH_PARAMETERS));
    }

    @Test
    public void withRequestParameter() {
        final Parameters requestAndBodyParameters = Parameters.from(JWT_PAYLOAD_PARAMETER);
        requestAndBodyParameters.put(
            "request",
            ImmutableMap.of("url", "/test_url")
        );

        MockRequest testRequest = mockRequest()
            .url("/wrong_url")
            .header("Authorization", TEST_AUTH_HEADER.toString());
        assertFalse(isExactMatch(testRequest, requestAndBodyParameters));

        testRequest.url("/test_url");
        assertTrue(isExactMatch(testRequest, requestAndBodyParameters));
    }

    @Test
    public void withArrayPayload() {
        final TestAuthHeader authHeaderWithAud = new TestAuthHeader(
            "{ \"test_header\": \"header_value\" }",
            "{ \"aud\": [\"foo\", \"bar\"] }"
        );
        final MockRequest request = mockRequest().header("Authorization", authHeaderWithAud.toString());

        final Parameters matchPayloadParams = Parameters.one(
            JwtMatcherExtension.PARAM_NAME_PAYLOAD,
            ImmutableMap.of("aud", new String[] { "foo", "bar" })
        );
        assertTrue(isExactMatch(request, matchPayloadParams));

        final Parameters noMatchPayloadParams = Parameters.one(
            JwtMatcherExtension.PARAM_NAME_PAYLOAD,
            ImmutableMap.of("aud", "foo")
        );
        assertFalse(isExactMatch(request, noMatchPayloadParams));
    }

    @Test
    public void withHeaderParameter() {
        final TestAuthHeader authHeaderWithAud = new TestAuthHeader(
            "{ \"test_header\": \"header_value\" }",
            "{ \"aud\": [\"foo\", \"bar\"] }"
        );
        final MockRequest request = mockRequest().header("x-key", authHeaderWithAud.toString());

        final Parameters matchPayloadParams = new Parameters() {
            {
                putAll(HEADER_PARAMETER);
                putAll(Parameters.one(
                        JwtMatcherExtension.PARAM_NAME_PAYLOAD,
                        ImmutableMap.of("aud", new String[] { "foo", "bar" })));
            }
        };

        assertTrue(isExactMatch(request, matchPayloadParams));

        final Parameters noMatchPayloadParams = new Parameters() {
            {
                putAll(HEADER_PARAMETER);
                putAll(Parameters.one(
                        JwtMatcherExtension.PARAM_NAME_PAYLOAD,
                        ImmutableMap.of("aud", "foo")));
            }
        };

        assertFalse(isExactMatch(request, noMatchPayloadParams));
    }

    @Test
    public void withQueryParameter() {
        final TestAuthHeader authHeaderWithAud = new TestAuthHeader(
            "{ \"test_header\": \"header_value\" }",
            "{ \"aud\": [\"foo\", \"bar\"] }"
        );
        final MockRequest request = mockRequest().url("?token=" + authHeaderWithAud.toString());

        final Parameters matchPayloadParams = new Parameters() {
            {
                putAll(QUERY_PARAMETER);
                putAll(Parameters.one(
                        JwtMatcherExtension.PARAM_NAME_PAYLOAD,
                        ImmutableMap.of("aud", new String[] { "foo", "bar" })));
            }
        };

        assertTrue(isExactMatch(request, matchPayloadParams));

        final Parameters noMatchPayloadParams = new Parameters() {
            {
                putAll(QUERY_PARAMETER);
                putAll(Parameters.one(
                        JwtMatcherExtension.PARAM_NAME_PAYLOAD,
                        ImmutableMap.of("aud", "foo")));
            }
        };

        assertFalse(isExactMatch(request, noMatchPayloadParams));
    }

    private boolean isExactMatch(MockRequest request, Parameters parameters) {
        return new JwtMatcherExtension().match(request.asLoggedRequest(), parameters).isExactMatch();
    }
}
