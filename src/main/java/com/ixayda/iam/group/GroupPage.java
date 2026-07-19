package com.ixayda.iam.group;

import java.util.List;

public record GroupPage(long totalResults, List<Group> groups) {

	public GroupPage {
		if (totalResults < 0) {
			throw new IllegalArgumentException("Group page total results must not be negative");
		}
		groups = List.copyOf(groups);
		if (groups.size() > totalResults) {
			throw new IllegalArgumentException("Group page cannot contain more groups than its total results");
		}
	}

}
