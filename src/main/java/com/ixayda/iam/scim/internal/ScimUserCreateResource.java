package com.ixayda.iam.scim.internal;

import java.util.Collection;
import java.util.List;

import com.unboundid.scim2.common.annotations.Schema;
import com.unboundid.scim2.common.types.UserResource;

@Schema(id = ScimUserSchema.URN, name = "User", description = "User Account")
final class ScimUserCreateResource extends UserResource {

	private boolean schemasProvided;

	private boolean schemasValid;

	@Override
	public void setSchemaUrns(Collection<String> schemaUrns) {
		this.schemasProvided = true;
		this.schemasValid = schemaUrns != null && schemaUrns.size() == 1
				&& ScimUserSchema.URN.equals(schemaUrns.iterator().next());
		super.setSchemaUrns(schemaUrns == null ? List.of() : schemaUrns);
	}

	boolean schemasProvided() {
		return this.schemasProvided;
	}

	boolean schemasValid() {
		return this.schemasValid;
	}

}
