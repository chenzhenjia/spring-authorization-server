package sample.handlers;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Optional;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.StringUtils;

/**
 * @author chenzhenjia
 */
public class OAuth2JsonAuthenticationFailureHandler implements AuthenticationFailureHandler {

	public static final Logger logger = LoggerFactory.getLogger(OAuth2JsonAuthenticationFailureHandler.class);
	private ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		OAuth2AuthorizationCodeRequestAuthenticationException authorizationCodeRequestAuthenticationException =
				(OAuth2AuthorizationCodeRequestAuthenticationException) exception;
		OAuth2Error error = authorizationCodeRequestAuthenticationException.getError();
		Optional<OAuth2AuthorizationCodeRequestAuthenticationToken> authorizationCodeRequestAuthentication = Optional.ofNullable(
				authorizationCodeRequestAuthenticationException.getAuthorizationCodeRequestAuthentication());

		String redirectUri = authorizationCodeRequestAuthentication.map(
				OAuth2AuthorizationCodeRequestAuthenticationToken::getRedirectUri).orElse(null);
		String state = authorizationCodeRequestAuthentication.map(
				OAuth2AuthorizationCodeRequestAuthenticationToken::getState).orElse(null);
		write(response, error, redirectUri, state);
	}

	private void write(HttpServletResponse response, OAuth2Error error, String redirectUri, String state)
			throws IOException {
		if (response.isCommitted()) {
			logger.warn("Response has already been committed. Unable to write error response");
			return;
		}
		response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
		response.setContentType("application/json;charset=UTF-8");
		try (JsonGenerator generator = objectMapper.getFactory()
				.createGenerator(response.getOutputStream(), JsonEncoding.UTF8)) {
			generator.writeStartObject();
			if (StringUtils.hasText(error.getUri())) {
				generator.writeStringField(OAuth2ParameterNames.ERROR_URI, error.getUri());
			}
			if (StringUtils.hasText(error.getDescription())) {
				generator.writeStringField(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
			}
			if (StringUtils.hasText(error.getErrorCode())) {
				generator.writeStringField(OAuth2ParameterNames.ERROR, error.getErrorCode());
			}
			if (StringUtils.hasText(state)) {
				generator.writeStringField(OAuth2ParameterNames.STATE, state);
			}
			if (StringUtils.hasText(redirectUri)) {
				generator.writeStringField(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
			}
			generator.writeEndObject();
			generator.flush();
		}
		response.flushBuffer();
	}
}
