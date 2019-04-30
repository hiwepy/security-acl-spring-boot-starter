package org.springframework.security.boot;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityAclProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityAclProperties.class, ServerProperties.class })
public class SecurityAclFilterConfiguration {
 
	@Configuration
    @ConditionalOnProperty(prefix = SecurityAclProperties.PREFIX, value = "enabled", havingValue = "true")
   	@EnableConfigurationProperties({ SecurityAclProperties.class, SecurityBizProperties.class })
	@Order(104)
   	static class AclWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {
    	
    	private ApplicationEventPublisher eventPublisher;
    	
        private final AuthenticationManager authenticationManager;
	    private final ObjectMapper objectMapper;
	    private final RememberMeServices rememberMeServices;
	    private final UserDetailsServiceAdapter userDetailsService;
	    private final PasswordEncoder passwordEncoder;
	    private final SessionRegistry sessionRegistry;
	    
    	private final SecurityAclProperties bizUpcProperties;
	    private final PostRequestAuthenticationEntryPoint authenticationEntryPoint;
	    private final DaoAuthenticationProvider authenticationProvider;
	    private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
	    private final CaptchaResolver captchaResolver;

		private final AuthenticatingFailureCounter authenticatingFailureCounter;
		private final CsrfTokenRepository csrfTokenRepository;
	    private final InvalidSessionStrategy invalidSessionStrategy;
    	private final RequestCache requestCache;
		private final SecurityContextLogoutHandler securityContextLogoutHandler;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionInformationExpiredStrategy expiredSessionStrategy;
   		
   		public AclWebSecurityConfigurerAdapter(
   			
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<UserDetailsServiceAdapter> userDetailsServiceProvider,
   				ObjectProvider<PasswordEncoder> passwordEncoderProvider,
   				ObjectProvider<SessionRegistry> sessionRegistryProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				
   				SecurityAclProperties bizUpcProperties,
   				ObjectProvider<PostRequestAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<DaoAuthenticationProvider> authenticationProvider,
   				ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				
   				@Qualifier("upcAuthenticatingFailureCounter") ObjectProvider<AuthenticatingFailureCounter> authenticatingFailureCounter,
   				@Qualifier("upcCsrfTokenRepository") ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				@Qualifier("upcInvalidSessionStrategy") ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
				@Qualifier("upcRequestCache") ObjectProvider<RequestCache> requestCacheProvider,
				@Qualifier("upcSecurityContextLogoutHandler")  ObjectProvider<SecurityContextLogoutHandler> securityContextLogoutHandlerProvider,
				@Qualifier("upcSessionAuthenticationStrategy") ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				@Qualifier("upcExpiredSessionStrategy") ObjectProvider<SessionInformationExpiredStrategy> expiredSessionStrategyProvider
			) {
   			
   			this.userDetailsService = userDetailsServiceProvider.getIfAvailable();
   			this.passwordEncoder = passwordEncoderProvider.getIfAvailable();
   			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionRegistry = sessionRegistryProvider.getIfAvailable();
   			
   			this.bizUpcProperties = bizUpcProperties;
   			this.authenticationEntryPoint = authenticationEntryPointProvider.getIfAvailable();
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			this.captchaResolver = captchaResolverProvider.getIfAvailable();
   			
   			this.authenticatingFailureCounter = authenticatingFailureCounter.getIfAvailable();
   			this.csrfTokenRepository = csrfTokenRepositoryProvider.getIfAvailable();
   			this.invalidSessionStrategy = invalidSessionStrategyProvider.getIfAvailable();
   			this.requestCache = requestCacheProvider.getIfAvailable();
   			this.securityContextLogoutHandler = securityContextLogoutHandlerProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			this.expiredSessionStrategy = expiredSessionStrategyProvider.getIfAvailable();
   			
   		}
   		
   		@Override
   	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
   	        auth.authenticationProvider(authenticationProvider)
   	        	.userDetailsService(userDetailsService)
   	            .passwordEncoder(passwordEncoder);
   	    }
   		
   	    @Override
   	    protected void configure(HttpSecurity http) throws Exception {
   	        http.authorizeRequests()
                .anyRequest()
                .fullyAuthenticated()
                .antMatchers("/oauth/token").permitAll()
                .and()
                .csrf().disable();
   	    }
   	    
   		@Override
   		public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
   			this.eventPublisher = applicationEventPublisher;
   		}

   	}

}
