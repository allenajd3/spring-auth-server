package com.ayg.auth.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.ayg.auth.server.config.grant.password.GrantPasswordAuthenticationProvider;
import com.ayg.auth.server.config.grant.password.OAuth2GrantPasswordAuthenticationConverter;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

	/*
	 * Publicación endpoints del server:
	 * http://localhost:9000/.well-known/oauth-authorization-server
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(
			HttpSecurity http,
			GrantPasswordAuthenticationProvider grantPasswordAuthenticationProvider
	) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
		.tokenEndpoint(tokenEndpoint ->
       			tokenEndpoint
       				.accessTokenRequestConverter(new OAuth2GrantPasswordAuthenticationConverter())
       				.authenticationProvider(grantPasswordAuthenticationProvider))
		.oidc(Customizer.withDefaults()); // Enable OpenID
																										// Connect 1.0
		http
				// Redirect to the login page when not authenticated from the
				// authorization endpoint
				.exceptionHandling((exceptions) -> 
					exceptions.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
					)
				)
				// Accept access tokens for User Info and/or Client Registration
				.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));

		return http.build();
	}

	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((authorize) -> 
		authorize.requestMatchers("/auth/**","/h2-console/**","/client/**","/login","/logout", "/error").permitAll()
			.anyRequest().authenticated())
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
			//.formLogin(Customizer.withDefaults())
			
			//Login custom (pendiente de hacer redirect)
			.formLogin(formLogin -> formLogin
					.loginPage("/login"))
			
			.csrf(csrf -> csrf.ignoringRequestMatchers("/auth/**","/h2-console/**","/client/**","/login"));
	
	//Necesario para el X_FRAME de H2_CONSOLE
	http.headers(headers -> headers.frameOptions(frameoptions -> frameoptions.disable()));
	
	return http.build();
	}
	
	@Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.debug(false)
                .ignoring()
                .requestMatchers("/webjars/**", "/images/**", "/css/**", "/assets/**", "/favicon.ico");
    }
	
	@Bean
	public GrantPasswordAuthenticationProvider grantPasswordAuthenticationProvider(
	   UserDetailsService userDetailsService, OAuth2TokenGenerator<?> jwtTokenCustomizer,
	   OAuth2AuthorizationService authorizationService, PasswordEncoder passwordEncoder
	) {
	   return new GrantPasswordAuthenticationProvider(
	       authorizationService, jwtTokenCustomizer, userDetailsService, passwordEncoder
	   );
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().issuer("http://127.0.0.1:9000").build();
	}
}
