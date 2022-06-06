/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;


@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class CustomConsentHandlerAuthorizationServerTests {

	@Autowired
	private MockMvc mockMvc;
	@Autowired
	private ObjectMapper objectMapper;
	@MockBean
	private OAuth2AuthorizationConsentService authorizationConsentService;

	private final String redirectUri = "http://127.0.0.1/login/oauth2/code/messaging-client-oidc";

	private final String authorizationRequestUri = UriComponentsBuilder
			.fromPath("/oauth2/authorize")
			.queryParam("response_type", "code")
			.queryParam("client_id", "messaging-client")
			.queryParam("scope", "openid message.read message.write")
			.queryParam("state", "state")
			.queryParam("redirect_uri", this.redirectUri)
			.build().toUriString();

	@Before
	public void setUp() {
		when(this.authorizationConsentService.findById(any(), any())).thenReturn(null);
	}

	@Test
	@WithMockUser("user1")
	public void whenUserConsentJsonHandler() throws Exception {
		MockHttpSession session = new MockHttpSession();
		MockHttpServletResponse response = mockMvc.perform(get(this.authorizationRequestUri).session(session))
				.andExpect(status().isOk())
				.andExpect(header().string("Content-Type", "application/json;charset=UTF-8"))
				.andExpect(jsonPath("$.consent_required").value(true))
				.andExpect(jsonPath("$.client_id").exists())
				.andExpect(jsonPath("$.state").exists())
				.andExpect(jsonPath("$.scope").exists())
				.andReturn()
				.getResponse();
		byte[] authorizeResponseBytes = response
				.getContentAsByteArray();
		JsonNode jsonNode = objectMapper.readTree(authorizeResponseBytes);
		List<String> scopes = new ArrayList<>();
		for (JsonNode scope : jsonNode.get("scope")) {
			scopes.add(scope.asText());
		}

		MockHttpServletResponse consentResponse = mockMvc.perform(
						get("/oauth2/consent?client_id={client_id}&state={state}&scope={scope}",
								jsonNode.get("client_id").asText(),
								jsonNode.get("state").asText(),
								String.join(" ", scopes))
								.session(session)
				)
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.principalName").value("user1"))
				.andExpect(jsonPath("$.scopes[*].scope").value(
						Matchers.hasItems("openid", "message.read", "message.write")))
				.andReturn()
				.getResponse();
		byte[] consentResponseBytes = consentResponse.getContentAsByteArray();
		JsonNode consentJsonNode = objectMapper.readTree(consentResponseBytes);

		mockMvc.perform(post("/oauth2/authorize")
						.contentType(MediaType.APPLICATION_FORM_URLENCODED)
						.param("client_id", consentJsonNode.get("clientId").asText())
						.param("state", consentJsonNode.get("state").asText())
						.param("scope", scopes.toArray(String[]::new))
				)
				.andExpect(status().isOk())
				.andExpect(header().string("Content-Type", "application/json;charset=UTF-8"))
				.andExpect(jsonPath("$.redirect_uri").exists())
				.andExpect(jsonPath("$.redirect_uri").value(Matchers.startsWith(this.redirectUri)))
		;

	}


}
