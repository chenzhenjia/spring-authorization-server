package sample.handlers;

import java.io.IOException;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.RedirectUrlBuilder;

/**
 * @author chenzhenjia
 */
public class FormLoginJsonAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private PortResolver portResolver = new PortResolverImpl();

	public void setPortResolver(PortResolver portResolver) {
		this.portResolver = portResolver;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		clearAuthenticationAttributes(request);
		if (response.isCommitted()) {
			return;
		}
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");
		HttpSession session = request.getSession(false);
		if (session != null) {
			Boolean oauth2Login = Optional.ofNullable(session.getAttribute("OAUTH2_LOGIN_STATE"))
					.filter(String.class::isInstance)
					.map(Object::toString)
					.map(s -> {
						String loginState = request.getParameter("loginState");
						return s.equals(loginState);
					})
					.orElse(false);
			if (oauth2Login) {
				response.setStatus(HttpServletResponse.SC_OK);
				int serverPort = portResolver.getServerPort(request);
				String scheme = request.getScheme();
				RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
				urlBuilder.setScheme(scheme);
				urlBuilder.setServerName(request.getServerName());
				urlBuilder.setPort(serverPort);
				urlBuilder.setContextPath(request.getContextPath());
				urlBuilder.setPathInfo("/oauth2/authorize");
				response.getWriter()
						.write("{\"auth_type\":\"oauth2\",\"authorize_url\":\"" + urlBuilder.getUrl() + "\"}");
				response.flushBuffer();
				return;
			}
		}
		response.setStatus(HttpServletResponse.SC_NO_CONTENT);
	}

	protected final void clearAuthenticationAttributes(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
		}
	}
}
