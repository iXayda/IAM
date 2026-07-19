package com.ixayda.iam.scim.internal;

import java.util.List;

record ScimGroupPage(long totalResults, List<ScimGroupView> groups) {

	ScimGroupPage {
		if (totalResults < 0) {
			throw new IllegalArgumentException("SCIM Group page total results must not be negative");
		}
		groups = List.copyOf(groups);
		if (groups.size() > totalResults) {
			throw new IllegalArgumentException("SCIM Group page cannot contain more groups than its total results");
		}
	}

}
