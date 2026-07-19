package com.ixayda.iam.scim.internal;

import java.io.IOException;

final class ScimPayloadTooLargeException extends IOException {

	ScimPayloadTooLargeException() {
		super("SCIM request body exceeds the configured byte limit");
	}

}
