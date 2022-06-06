package sample.handlers;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author chenzhenjia
 */
public class OAuth2JsonAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
				.queryParam(OAuth2ParameterNames.CODE,
						authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue());
		if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE, authorizationCodeRequestAuthentication.getState());
		}
		response.setStatus(HttpServletResponse.SC_OK);
		response.setContentType("application/json;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		response.getWriter()
				.write("{\"" + OAuth2ParameterNames.REDIRECT_URI + "\":\"" + uriBuilder.toUriString() + "\"}");
	}
}
