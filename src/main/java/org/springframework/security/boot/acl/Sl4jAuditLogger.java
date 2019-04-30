/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.acl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.acls.domain.AuditLogger;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.AuditableAccessControlEntry;
import org.springframework.util.Assert;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">wandl</a>
 */
public class Sl4jAuditLogger implements AuditLogger {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	@Override
	public void logIfNeeded(boolean granted, AccessControlEntry ace) {
		Assert.notNull(ace, "AccessControlEntry required");

		if (ace instanceof AuditableAccessControlEntry) {
			AuditableAccessControlEntry auditableAce = (AuditableAccessControlEntry) ace;

			if (granted && auditableAce.isAuditSuccess()) {
				logger.info("GRANTED due to ACE: " + ace);
			}
			else if (!granted && auditableAce.isAuditFailure()) {
				logger.info("DENIED due to ACE: " + ace);
			}
		}
	}

}
