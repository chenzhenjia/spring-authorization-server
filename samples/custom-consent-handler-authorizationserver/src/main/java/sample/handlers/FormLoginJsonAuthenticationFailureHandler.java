package sample.handlers;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * @author chenzhenjia
 */
public class FormLoginJsonAuthenticationFailureHandler implements AuthenticationFailureHandler {

  public final Map<Class<? extends AuthenticationException>, String> exceptionTypeMapping;

  public FormLoginJsonAuthenticationFailureHandler() {
    this.exceptionTypeMapping = new HashMap<>();
    this.exceptionTypeMapping.put(BadCredentialsException.class, "bad_credentials");
    this.exceptionTypeMapping.put(AccountExpiredException.class, "account_expired");
    this.exceptionTypeMapping.put(DisabledException.class, "account_disabled");
    this.exceptionTypeMapping.put(UsernameNotFoundException.class, "username_not_found");
  }

  public FormLoginJsonAuthenticationFailureHandler(Map<Class<? extends AuthenticationException>, String> exceptionTypeMapping) {
    this.exceptionTypeMapping = exceptionTypeMapping;
  }

  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) throws IOException {
    HttpStatus status = HttpStatus.UNAUTHORIZED;
    response.setStatus(status.value());
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");
    String type = Optional.ofNullable(exceptionTypeMapping.get(exception.getClass()))
        .orElse("authentication_failed");

    response.getWriter().write(
        "{\"" + OAuth2ParameterNames.ERROR + ":\"" + type + "\"," +
            OAuth2ParameterNames.ERROR_DESCRIPTION + "\":\""
            + exception.getMessage() + "\"}");
    response.flushBuffer();
  }
}
