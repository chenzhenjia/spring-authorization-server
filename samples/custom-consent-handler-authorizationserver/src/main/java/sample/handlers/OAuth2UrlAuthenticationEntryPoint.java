package sample.handlers;

import java.util.Base64;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author chenzhenjia
 */
public class OAuth2UrlAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

	private static final StringKeyGenerator DEFAULT_STATE_GENERATOR =
			new Base64StringKeyGenerator(Base64.getUrlEncoder());

	public OAuth2UrlAuthenticationEntryPoint(String loginFormUrl) {
		super(loginFormUrl);
	}

	@Override
	protected String buildRedirectUrlToLoginPage(HttpServletRequest request,
			HttpServletResponse response, AuthenticationException authException) {
		String httpUrl = super.buildRedirectUrlToLoginPage(request, response, authException);
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(httpUrl)
				.query(Optional.ofNullable(request.getQueryString()).orElse(""));
		HttpSession session = request.getSession(false);
		if (session != null) {
			String loginState = DEFAULT_STATE_GENERATOR.generateKey();
			uriComponentsBuilder.queryParam("login_state", loginState);
			session.setAttribute("OAUTH2_LOGIN_STATE", loginState);
		}
		return uriComponentsBuilder
				.toUriString();
	}
}
