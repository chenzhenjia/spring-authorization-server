package sample.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ConsentHandler;

/**
 * @author chenzhenjia
 */
public class JsonOAuth2ConsentHandler implements OAuth2ConsentHandler {

	private ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public void handleConsent(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult)
			throws IOException, ServletException {
		if (response.isCommitted()) {
			return;
		}
		String clientId = authorizationCodeRequestAuthenticationResult.getClientId();
		String state = authorizationCodeRequestAuthenticationResult.getState();
		Map<String, Object> result = new HashMap<>();
		result.put("consent_required", authorizationCodeRequestAuthenticationResult.isConsentRequired());
		result.put("consent", authorizationCodeRequestAuthenticationResult.isConsent());
		result.put(OAuth2ParameterNames.CLIENT_ID, clientId);
		result.put(OAuth2ParameterNames.STATE, state);
		result.put(OAuth2ParameterNames.SCOPE, authorizationCodeRequestAuthentication.getScopes());
		response.setContentType("application/json;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(objectMapper.writeValueAsString(result));
		response.getWriter().flush();
	}
}
