package com.ixayda.iam.user;

/**
 * Participates synchronously in a user deletion transaction before the user is
 * marked deleted. The caller holds an exclusive tenant write guard and an
 * exclusive lock on the user, so implementations must complete in the existing
 * transaction.
 */
public interface UserDeletionParticipant {

	void beforeDelete(User user);

}
