package com.ixayda.iam.user;

import java.util.List;

public record UserPage(long totalResults, List<User> users) {

	public UserPage {
		if (totalResults < 0) {
			throw new IllegalArgumentException("User page total results must not be negative");
		}
		users = List.copyOf(users);
		if (users.size() > totalResults) {
			throw new IllegalArgumentException("User page cannot contain more users than its total results");
		}
	}

}
