package org.springframework.security.boot;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.AuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.SpringCacheBasedAclCache;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.boot.acl.Sl4jAuditLogger;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * <p>
 * https://elim.iteye.com/blog/2269021
 * </p>
 * <p>
 * <b>Sid：</b>可以用来表示一个principal，或者是一个GrantedAuthority。其对应的实现类有表示principal的PrincipalSid和表示GrantedAuthority的GrantedAuthoritySid。其信息会保存在acl_sid表中。
 * </p>
 * <p>
 * <b>ObjectIdentity：</b>ObjectIdentity表示Spring Security
 * Acl中一个域对象，其默认实现类是ObjectIdentityImpl。ObjectIdentity并不是直接与acl_object_identity表相对应的，真正与acl_object_identity表直接相对应的是Acl。
 * </p>
 * <p>
 * <b>Acl：</b>每一个领域对象都会对应一个Acl，而且只会对应一个Acl。Acl是将Spring Security
 * Acl中使用到的四个表串联起来的一个接口，其中会包含对象信息ObjectIdentity、对象的拥有者Sid和对象的访问控制信息AccessControlEntry。在Spring
 * Security
 * Acl中直接与acl_object_identity表相关联的是Acl接口，因为acl_object_identity表中的数据是通过保存Acl来进行的。一个Acl对应于一个ObjectIdentity，但是会包含有多个Sid和多个AccessControlEntry，即一个Acl表示所有Sid对一个ObjectIdentity的所有AccessControlEntry。Acl的默认实现类是AclImpl，该类实现Acl接口、MutableAcl接口、AuditableAcl接口和OwnershipAcl接口。
 * </p>
 * <p>
 * <b>AccessControlEntry：</b>一个AccessControlEntry表示一条访问控制信息，一个Acl中可以拥有多个AccessControlEntry。在Spring
 * Security Acl中很多地方会使用ACE来简单的表示AccessControlEntry这个概念，比如insertAce其实表示的就是insert
 * AccessControlEntry。每一个AccessControlEntry表示对应的Sid对于对应的对象ObjectIdentity是否被授权某一项权限Permission，是否被授权将使用granting进行区分。AccessControlEntry对应表acl_entry。
 * </p>
 * <p>
 * <b>Permission：</b>在Acl中使用一个bit掩码来表示一个Permission。Spring
 * Security的Acl中默认使用的是BasePermission，其中已经定义了0-4五个bit掩码，分别对应于1、2、4、8、16，代表五种不同的Permission，分别是read
 * (bit 0)、write (bit 1)、create (bit 2)、delete (bit 3)和administer (bit
 * 4)。如果已经定义好的这五个bit掩码不能满足需求，我们可以对BasePermission进行扩展，也可以实现自己的Permission。Spring
 * Security Acl默认的实现最多可以支持32个不同的掩码。
 * </p>
 * <p>
 * <b>AclService：</b>AclService是用来通过ObjectIdentity解析Acl的，其默认实现类是JdbcAclService。JdbcAclService底层操作是通过LookupStrategy来进行的，LookupStrategy的默认实现是BasicLookupStrategy。
 * </p>
 * <p>
 * <b>MutableAclService：</b>MutableAclService是用来对Acl进行持久化的，其默认实现类是JdbcMutableAclService。JdbcMutableAclService是继承自JdbcAclService的，所以我们可以同时通过JdbcMutableAclService对Acl进行读取和保存。如果我们希望自己来实现Acl信息的保存的话，我们也可以不使用该接口。
 * </p>
 */
@Configuration
@AutoConfigureBefore({ SecurityAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityAclProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityAclProperties.class })
public class SecurityAclAutoConfiguration {

	@Autowired
	private SecurityAclProperties aclProperties;
	@Autowired
	private CacheManager cacheManager;

	@Bean
	@ConditionalOnMissingBean
	protected AuditLogger auditLogger() {
		return new Sl4jAuditLogger();
	}

	@Bean
	@ConditionalOnMissingBean
	protected PermissionGrantingStrategy permissionGrantingStrategy(AuditLogger auditLogger) {
		return new DefaultPermissionGrantingStrategy(auditLogger);
	}

	@Bean
	@ConditionalOnMissingBean
	protected AclAuthorizationStrategy aclAuthorizationStrategy() {
		// 改变所有权需要的权限
		GrantedAuthority gaGeneralChanges = new SimpleGrantedAuthority("ROLE_ADMIN");
		// 改变授权需要的权限
		GrantedAuthority gaModifyAuditing = new SimpleGrantedAuthority("gaModifyAuditing" );;
		// 改变其它信息所需要的权限
		GrantedAuthority gaTakeOwnership = new SimpleGrantedAuthority("gaGeneralChanges" );
		
		return new AclAuthorizationStrategyImpl(gaGeneralChanges, gaModifyAuditing, gaTakeOwnership);
	}

	@Bean
	@ConditionalOnMissingBean
	protected AclCache aclCache(PermissionGrantingStrategy permissionGrantingStrategy,
			AclAuthorizationStrategy aclAuthorizationStrategy) {

		Cache cache = cacheManager.getCache("ACL");

		return new SpringCacheBasedAclCache(cache, permissionGrantingStrategy, aclAuthorizationStrategy);
	}

	@Bean
	@ConditionalOnMissingBean
	protected LookupStrategy lookupStrategy(DataSource dataSource, AclCache aclCache,
			AclAuthorizationStrategy aclAuthorizationStrategy, PermissionGrantingStrategy permissionGrantingStrategy) {
		return new BasicLookupStrategy(dataSource, aclCache, aclAuthorizationStrategy, permissionGrantingStrategy);
	}

	@Bean
	@ConditionalOnMissingBean
	protected AclService aclService(DataSource dataSource, LookupStrategy lookupStrategy, AclCache aclCache) {
		
		JdbcMutableAclService aclService = new JdbcMutableAclService(dataSource, lookupStrategy, aclCache);

		/*
		 * 指定相关SQL https://www.cnblogs.com/xm1-ybtk/p/5111926.html
		 */
		aclService.setAclClassIdSupported(aclProperties.isAclClassIdSupported());
		// 查询刚刚新增的acl_class的主键的SQL
		aclService.setClassIdentityQuery(aclProperties.getClassIdentityQuerySql());
		aclService.setClassPrimaryKeyQuery(aclProperties.getSelectClassPrimaryKeySql());
		aclService.setDeleteEntryByObjectIdentityForeignKeySql(aclProperties.getDeleteEntryByObjectIdentityForeignKeySql());
		aclService.setDeleteObjectIdentityByPrimaryKeySql(aclProperties.getDeleteObjectIdentityByPrimaryKeySql());
		//aclService.setFindChildrenQuery(aclProperties.get);
		aclService.setForeignKeysInDatabase(aclProperties.isForeignKeysInDatabase());
		// 指定新增acl_class的脚本
		aclService.setInsertClassSql(aclProperties.getInsertClassSql());
		// 指定新增acl_entry的脚本
		aclService.setInsertEntrySql(aclProperties.getInsertEntrySql());
		// 指定新增acl_object_identity的脚本
		aclService.setInsertObjectIdentitySql(aclProperties.getInsertObjectIdentitySql());
		// 指定新增acl_sid的脚本
		aclService.setInsertSidSql(aclProperties.getInsertSidSql());
		aclService.setObjectIdentityPrimaryKeyQuery(aclProperties.getSelectObjectIdentityPrimaryKeySql());
		// 查询刚刚新增的acl_sid的主键的SQL
		aclService.setSidIdentityQuery(aclProperties.getSidIdentityQuerySql());
		aclService.setSidPrimaryKeyQuery(aclProperties.getSelectSidPrimaryKeySql());
		aclService.setUpdateObjectIdentity(aclProperties.getUpdateObjectIdentitySql());
		
		return aclService;
	}

	
	
	@Bean
	@ConditionalOnMissingBean
	protected MethodSecurityExpressionHandler methodSecurityExpressionHandler(AclPermissionEvaluator aclPermissionEvaluator) {
		DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		expressionHandler.setPermissionEvaluator(aclPermissionEvaluator);
		
		return expressionHandler;
	}
	
	
	@Bean
	@ConditionalOnMissingBean
	protected AclPermissionEvaluator aclPermissionEvaluator(AclService aclService) {
		return new AclPermissionEvaluator(aclService);
	}
	
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
