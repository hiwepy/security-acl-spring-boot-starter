package org.springframework.security.boot;

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.acls.model.AclCache;

@ConfigurationProperties(prefix = SecurityAclProperties.PREFIX)
public class SecurityAclProperties {

	public static final String PREFIX = "spring.security.acl";

	/**
	 * Enable Security ACL.
	 */
	private boolean enabled = false;

	private boolean forcePrincipalAsString = false;
	protected boolean hideUserNotFoundExceptions = true;

	private boolean useAuthenticationRequestCredentials = true;

	private String[] ldapUrls;

	/** The url of the LDAP server. */
	private String[] urls;

	private boolean pooled = false;

	private String groupSearchBase = "";

	private boolean anonymousReadOnly = false;

	private String referral = null;

	/** ldap://192.168.0.1:389/dc=gnetis,dc=com */
	private String providerUrl;

	/** cn=Manager,dc=gnetis,dc=com */
	private String userDn;

	private String password;

	/**
	 * The base suffix from which all operations should origin. If a base suffix is
	 * set, you will not have to (and, indeed, must not) specify the full
	 * distinguished names in any operations performed.
	 */
	private String base;

	private Map<String, Object> baseEnvironmentProperties;

	private boolean cacheEnvironmentProperties = true;
	/** FilterBasedLdapUserSearch */

	/**
	 * Context name to search in, relative to the base of the configured
	 * ContextSource.
	 */
	private String searchBase = "";

	/**
	 * The filter expression used in the user search. This is an LDAP search filter
	 * (as defined in 'RFC 2254') with optional arguments. See the documentation for
	 * the <tt>search</tt> methods in {@link javax.naming.directory.DirContext
	 * DirContext} for more information.
	 *
	 * <p>
	 * In this case, the username is the only parameter.
	 * </p>
	 * Possible examples are:
	 * <ul>
	 * <li>(uid={0}) - this would search for a username match on the uid
	 * attribute.</li>
	 * </ul>
	 */
	private String searchFilter;

	/** The derefLinkFlag value as defined in SearchControls.. */
	private boolean derefLinkFlag;
	/**
	 * Specifies the attributes that will be returned as part of the search.
	 * <p>
	 * null indicates that all attributes will be returned. An empty array indicates
	 * no attributes are returned.
	 */
	public String[] returningAttrs = new String[] {};
	/**
	 * If true then searches the entire subtree as identified by context, if false
	 * (the default) then only searches the level identified by the context.
	 */
	private boolean searchSubtree;
	/**
	 * The time to wait before the search fails (in milliseconds); the default is
	 * zero, meaning forever.
	 */
	private int searchTimeLimit;

	// ~ Instance fields
	// ================================================================================================
	private boolean aclClassIdSupported;
	
	private boolean foreignKeysInDatabase = true;
	private String deleteEntryByObjectIdentityForeignKeySql = "delete from acl_entry where acl_object_identity=?";
	private String deleteObjectIdentityByPrimaryKeySql = "delete from acl_object_identity where id=?";
	/**
	 * 查询刚刚新增的acl_class的主键的SQL
	 */
	private String classIdentityQuerySql = "select seq_acl_class.currval from dual";
	/**
	 * 查询刚刚新增的acl_sid的主键的SQL
	 */
	private String sidIdentityQuerySql =  "select seq_acl_sid.currval from dual";
	/**
	 * 指定新增acl_class的脚本
	 */
	private String insertClassSql = "insert into acl_class(id, class) values (seq_acl_class.nextval, ?)";
	/**
	 * 指定新增acl_entry的脚本
	 */
	private String insertEntrySql =  "insert into acl_entry(id, acl_object_identity, ace_order, sid, mask, granting, audit_success, audit_failure) values (seq_acl_entry.nextval, ?, ?, ?, ?, ?, ?, ?)";
	/**
	 * 指定新增acl_object_identity的脚本
	 */
	private String insertObjectIdentitySql = "insert into acl_object_identity(id, object_id_class, object_id_identity, owner_sid, entries_inheriting) values(seq_acl_object_identity.nextval, ?, ?, ?, ?)";
	/**
	 * 指定新增acl_sid的脚本
	 */
	private String insertSidSql = "insert into acl_sid(id, principal, sid) values (seq_acl_sid.nextval, ?, ?)";
	private String selectClassPrimaryKeySql = "select id from acl_class where class=?";
	private String selectObjectIdentityPrimaryKeySql = "select acl_object_identity.id from acl_object_identity, acl_class "
			+ "where acl_object_identity.object_id_class = acl_class.id and acl_class.class=? "
			+ "and acl_object_identity.object_id_identity = ?";
	private String selectSidPrimaryKeySql = "select id from acl_sid where principal=? and sid=?";
	private String updateObjectIdentitySql = "update acl_object_identity set "
			+ "parent_object = ?, owner_sid = ?, entries_inheriting = ?" + " where id = ?";

	public boolean isForcePrincipalAsString() {
		return forcePrincipalAsString;
	}

	public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
		this.forcePrincipalAsString = forcePrincipalAsString;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public boolean isUseAuthenticationRequestCredentials() {
		return useAuthenticationRequestCredentials;
	}

	public void setUseAuthenticationRequestCredentials(boolean useAuthenticationRequestCredentials) {
		this.useAuthenticationRequestCredentials = useAuthenticationRequestCredentials;
	}

	public String[] getLdapUrls() {
		return ldapUrls;
	}

	public void setLdapUrls(String[] ldapUrls) {
		this.ldapUrls = ldapUrls;
	}

	public String[] getUrls() {
		return urls;
	}

	public void setUrls(String[] urls) {
		this.urls = urls;
	}

	public boolean isPooled() {
		return pooled;
	}

	public void setPooled(boolean pooled) {
		this.pooled = pooled;
	}

	public String getGroupSearchBase() {
		return groupSearchBase;
	}

	public void setGroupSearchBase(String groupSearchBase) {
		this.groupSearchBase = groupSearchBase;
	}

	public boolean isAnonymousReadOnly() {
		return anonymousReadOnly;
	}

	public void setAnonymousReadOnly(boolean anonymousReadOnly) {
		this.anonymousReadOnly = anonymousReadOnly;
	}

	public String getReferral() {
		return referral;
	}

	public void setReferral(String referral) {
		this.referral = referral;
	}

	public String getProviderUrl() {
		return providerUrl;
	}

	public void setProviderUrl(String providerUrl) {
		this.providerUrl = providerUrl;
	}

	public String getUserDn() {
		return userDn;
	}

	public void setUserDn(String userDn) {
		this.userDn = userDn;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getBase() {
		return base;
	}

	public void setBase(String base) {
		this.base = base;
	}

	public Map<String, Object> getBaseEnvironmentProperties() {
		return baseEnvironmentProperties;
	}

	public void setBaseEnvironmentProperties(Map<String, Object> baseEnvironmentProperties) {
		this.baseEnvironmentProperties = baseEnvironmentProperties;
	}

	public boolean isCacheEnvironmentProperties() {
		return cacheEnvironmentProperties;
	}

	public void setCacheEnvironmentProperties(boolean cacheEnvironmentProperties) {
		this.cacheEnvironmentProperties = cacheEnvironmentProperties;
	}

	public String getSearchBase() {
		return searchBase;
	}

	public void setSearchBase(String searchBase) {
		this.searchBase = searchBase;
	}

	public String getSearchFilter() {
		return searchFilter;
	}

	public void setSearchFilter(String searchFilter) {
		this.searchFilter = searchFilter;
	}

	public boolean isDerefLinkFlag() {
		return derefLinkFlag;
	}

	public void setDerefLinkFlag(boolean derefLinkFlag) {
		this.derefLinkFlag = derefLinkFlag;
	}

	public String[] getReturningAttrs() {
		return returningAttrs;
	}

	public void setReturningAttrs(String[] returningAttrs) {
		this.returningAttrs = returningAttrs;
	}

	public boolean isSearchSubtree() {
		return searchSubtree;
	}

	public void setSearchSubtree(boolean searchSubtree) {
		this.searchSubtree = searchSubtree;
	}

	public int getSearchTimeLimit() {
		return searchTimeLimit;
	}

	public void setSearchTimeLimit(int searchTimeLimit) {
		this.searchTimeLimit = searchTimeLimit;
	}
	
	

	public boolean isAclClassIdSupported() {
		return aclClassIdSupported;
	}

	public void setAclClassIdSupported(boolean aclClassIdSupported) {
		this.aclClassIdSupported = aclClassIdSupported;
	}

	public boolean isHideUserNotFoundExceptions() {
		return hideUserNotFoundExceptions;
	}

	public void setHideUserNotFoundExceptions(boolean hideUserNotFoundExceptions) {
		this.hideUserNotFoundExceptions = hideUserNotFoundExceptions;
	}

	public boolean isForeignKeysInDatabase() {
		return foreignKeysInDatabase;
	}

	public String getDeleteEntryByObjectIdentityForeignKeySql() {
		return deleteEntryByObjectIdentityForeignKeySql;
	}

	public String getDeleteObjectIdentityByPrimaryKeySql() {
		return deleteObjectIdentityByPrimaryKeySql;
	}

	public String getClassIdentityQuerySql() {
		return classIdentityQuerySql;
	}

	public String getSidIdentityQuerySql() {
		return sidIdentityQuerySql;
	}

	public String getInsertClassSql() {
		return insertClassSql;
	}

	public String getInsertEntrySql() {
		return insertEntrySql;
	}

	public String getInsertObjectIdentitySql() {
		return insertObjectIdentitySql;
	}

	public String getInsertSidSql() {
		return insertSidSql;
	}

	public String getSelectClassPrimaryKeySql() {
		return selectClassPrimaryKeySql;
	}

	public String getSelectObjectIdentityPrimaryKeySql() {
		return selectObjectIdentityPrimaryKeySql;
	}

	public String getSelectSidPrimaryKeySql() {
		return selectSidPrimaryKeySql;
	}

	public String getUpdateObjectIdentitySql() {
		return updateObjectIdentitySql;
	}

	public void setForeignKeysInDatabase(boolean foreignKeysInDatabase) {
		this.foreignKeysInDatabase = foreignKeysInDatabase;
	}

	public void setDeleteEntryByObjectIdentityForeignKeySql(String deleteEntryByObjectIdentityForeignKeySql) {
		this.deleteEntryByObjectIdentityForeignKeySql = deleteEntryByObjectIdentityForeignKeySql;
	}

	public void setDeleteObjectIdentityByPrimaryKeySql(String deleteObjectIdentityByPrimaryKeySql) {
		this.deleteObjectIdentityByPrimaryKeySql = deleteObjectIdentityByPrimaryKeySql;
	}

	public void setClassIdentityQuerySql(String classIdentityQuerySql) {
		this.classIdentityQuerySql = classIdentityQuerySql;
	}

	public void setSidIdentityQuerySql(String sidIdentityQuerySql) {
		this.sidIdentityQuerySql = sidIdentityQuerySql;
	}

	public void setInsertClassSql(String insertClassSql) {
		this.insertClassSql = insertClassSql;
	}

	public void setInsertEntrySql(String insertEntrySql) {
		this.insertEntrySql = insertEntrySql;
	}

	public void setInsertObjectIdentitySql(String insertObjectIdentitySql) {
		this.insertObjectIdentitySql = insertObjectIdentitySql;
	}

	public void setInsertSidSql(String insertSidSql) {
		this.insertSidSql = insertSidSql;
	}

	public void setSelectClassPrimaryKeySql(String selectClassPrimaryKeySql) {
		this.selectClassPrimaryKeySql = selectClassPrimaryKeySql;
	}

	public void setSelectObjectIdentityPrimaryKeySql(String selectObjectIdentityPrimaryKeySql) {
		this.selectObjectIdentityPrimaryKeySql = selectObjectIdentityPrimaryKeySql;
	}

	public void setSelectSidPrimaryKeySql(String selectSidPrimaryKeySql) {
		this.selectSidPrimaryKeySql = selectSidPrimaryKeySql;
	}

	public void setUpdateObjectIdentitySql(String updateObjectIdentitySql) {
		this.updateObjectIdentitySql = updateObjectIdentitySql;
	}

}
