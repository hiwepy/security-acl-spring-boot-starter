/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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

import org.springframework.security.acls.domain.BasePermission;

/**
 * https://elim.iteye.com/blog/2269021
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */

public class BasePermissionExt extends BasePermission {
	
	public BasePermissionExt(int mask) {
		super(mask);
	}

	public BasePermissionExt(int mask, char code) {
		super(mask, code);
	}
	
}
