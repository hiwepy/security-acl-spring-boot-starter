package org.springframework.security.boot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@AutoConfigureBefore({SecurityAutoConfiguration.class})
@ConditionalOnProperty(prefix = SecurityAclProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityAclProperties.class })
public class SecurityAclAutoConfiguration {

	@Autowired
	private SecurityAclProperties aclProperties;

	@Bean
	@ConditionalOnMissingBean
	protected UserCache userCache() {
		return new NullUserCache();
	}
	
	@Bean
	@ConditionalOnMissingBean
	protected GrantedAuthoritiesMapper authoritiesMapper() {
		return new NullAuthoritiesMapper();
	}
	
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsServiceAdapter userDetailsService,
			GrantedAuthoritiesMapper authoritiesMapper, PasswordEncoder passwordEncoder, UserCache userCache) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setAuthoritiesMapper(authoritiesMapper);
		provider.setForcePrincipalAsString(aclProperties.isForcePrincipalAsString());
		provider.setHideUserNotFoundExceptions(aclProperties.isHideUserNotFoundExceptions());
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserCache(userCache);
		provider.setUserDetailsPasswordService(userDetailsService);
		provider.setUserDetailsService(userDetailsService);
		return provider;
	}

}
