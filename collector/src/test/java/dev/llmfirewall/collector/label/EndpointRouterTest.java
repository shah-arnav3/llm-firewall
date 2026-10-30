package dev.llmfirewall.collector.label;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class EndpointRouterTest {

    private static final String ORG = "02812373-138d-4a58-874b-33e46fa50871";
    private static final String CONV = "f85e431c-3b8b-4dc7-aaa0-6ec211804df8";

    private final EndpointRouter router = new EndpointRouter();

    @Test
    void routesTheCompletionEndpoint() {
        final EndpointKey key = router.route("claude.ai", "POST",
                                             "/api/organizations/" + ORG + "/chat_conversations/" + CONV + "/completion");
        assertEquals(new EndpointKey("completion", "claude.ai", "POST",
                                     "/api/organizations/{org}/chat_conversations/{conv}/completion",
                                     Map.of("org", ORG, "conv", CONV), true),
                     key);
    }

    @Test
    void routesTitlesAndTheMessagesApi() {
        assertEquals("title", router.route("claude.ai", "POST",
                                           "/api/organizations/" + ORG + "/chat_conversations/" + CONV + "/title").name());
        assertEquals("generate_title", router.route("claude.ai", "POST",
                                                    "/api/organizations/" + ORG + "/dust/generate_title_and_branch").name());
        final EndpointKey messages = router.route("API.Anthropic.com", "post", "/v1/messages?beta=true");
        assertEquals("messages_api", messages.name());
        assertEquals("api.anthropic.com", messages.host());
        assertEquals("POST", messages.method());
        assertEquals(Map.of(), messages.pathParams());
    }

    @Test
    void theMethodHostAndShapeMustAllMatch() {
        assertFalse(router.route("claude.ai", "GET", "/api/organizations/" + ORG + "/chat_conversations/" + CONV + "/completion").known());
        assertFalse(router.route("evil.example", "POST", "/v1/messages").known());
        assertFalse(router.route("api.anthropic.com", "POST", "/v1/messages/count_tokens").known());
        assertFalse(router.route("claude.ai", "POST", "/api/organizations//chat_conversations/" + CONV + "/completion").known(),
                    "a variable needs a non-empty segment");
    }

    @Test
    void templatesUnknownPathsWithoutTheirIds() {
        final EndpointKey key = router.route("claude.ai", "GET", "/api/organizations/" + ORG + "/chat_conversations/" + CONV
                                                                 + "?tree=True&rendering_mode=messages");
        assertFalse(key.known());
        assertEquals("", key.name());
        assertEquals("/api/organizations/{id}/chat_conversations/{id}", key.pathTemplate());
        assertEquals("/api/bootstrap/{id}/app_start", router.route("claude.ai", "GET", "/api/bootstrap/123/app_start").pathTemplate());
        assertEquals("/cdn-cgi/challenge-platform/h/b/jsd/oneshot/{id}/{id}/{id}",
                     router.route("claude.ai", "POST", "/cdn-cgi/challenge-platform/h/b/jsd/oneshot/d2d3316b729e/"
                                                       + "0.9143971869041332:1792858212:V8YJ/a4fa94d39adc7818").pathTemplate());
    }

    @Test
    void keepsWordsVersionsAndRpcNames() {
        for (String path : new String[] {"/api/event_logging/v2/batch", "/v1/code/sessions", "/api/eval/sdk-zAZezfDKGoZuXXKe",
                                         "/claudeai-rpc/anthropic.loupe.api.v1alpha.OrgSurveyService/GetPendingSurvey",
                                         "/api/desktop/features", "/"}) {
            assertEquals(path, router.route("claude.ai", "POST", path).pathTemplate(), path);
        }
        assertTrue(router.route("claude.ai", "POST", "/").pathParams().isEmpty());
    }
}
