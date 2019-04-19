package org.springframework.security.boot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.acl.authentication.LadpAuthenticationProcessingFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.util.StringUtils;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityAclProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityAclProperties.class, ServerProperties.class })
public class SecurityAclFilterConfiguration extends WebSecurityConfigurerAdapter
		implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;
	@Autowired
	private SecurityAclProperties ldapProperties;
	
	@Bean
	public LadpAuthenticationProcessingFilter ladpAuthenticationProcessingFilter(
			AuthenticationManager authenticationManager, 
			AuthenticationSuccessHandler successHandler, 
    		AuthenticationFailureHandler failureHandler,
			RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy,
			@Autowired(required = false) CaptchaResolver captchaResolver,
			MessageSource messageSource,
			ObjectMapper objectMapper) {
		
		// Form Login With LDAP 
		LadpAuthenticationProcessingFilter authcFilter = new LadpAuthenticationProcessingFilter(objectMapper, ldapProperties);
		
		authcFilter.setCaptchaParameter(bizProperties.getCaptcha().getParamName());
		// 是否验证码必填
		authcFilter.setCaptchaRequired(bizProperties.getCaptcha().isRequired());
		// 登陆失败重试次数，超出限制需要输入验证码
		authcFilter.setRetryTimesWhenAccessDenied(bizProperties.getCaptcha().getRetryTimesWhenAccessDenied());
		// 验证码解析器
		authcFilter.setCaptchaResolver(captchaResolver);
		
		authcFilter.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(failureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(successHandler);
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getAuthc().getLoginUrlPatterns())) {
			authcFilter.setFilterProcessesUrl(bizProperties.getAuthc().getLoginUrlPatterns());
		}
		authcFilter.setMessageSource(messageSource);
		authcFilter.setPasswordParameter(bizProperties.getAuthc().getPasswordParameter());
		authcFilter.setPostOnly(bizProperties.getAuthc().isPostOnly());
		authcFilter.setRememberMeServices(rememberMeServices);
		
		authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
		
		authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
		authcFilter.setUsernameParameter(bizProperties.getAuthc().getUsernameParameter());

		return authcFilter;
	}
	
	@Autowired
	private LadpAuthenticationProcessingFilter ladpAuthenticationProcessingFilter;
	@Autowired
	private AbstractLdapAuthenticationProvider ldapAuthenticationProvider;
	 
	@Override
	protected void configure(AuthenticationManagerBuilder auth) {
		// 配置LDAP的验证方式
		auth.authenticationProvider(ldapAuthenticationProvider);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(ladpAuthenticationProcessingFilter, PostUsernamePasswordCaptchaAuthenticationProcessingFilter.class);
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

}
