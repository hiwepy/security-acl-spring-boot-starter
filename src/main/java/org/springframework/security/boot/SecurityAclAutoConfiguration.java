package org.springframework.security.boot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@AutoConfigureBefore({SecurityAutoConfiguration.class})
@ConditionalOnProperty(prefix = SecurityAclProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityAclProperties.class })
public class SecurityAclAutoConfiguration {

	@Autowired
	private SecurityAclProperties ldapProperties;
 

}
