package com.ixayda.iam.scim.internal;

import java.util.Collection;
import java.util.List;

import com.unboundid.scim2.common.annotations.Schema;
import com.unboundid.scim2.common.types.GroupResource;

@Schema(id = ScimGroupSchema.URN, name = "Group", description = "Group")
final class ScimGroupCreateResource extends GroupResource {

	private boolean schemasProvided;

	private boolean schemasValid;

	@Override
	public void setSchemaUrns(Collection<String> schemaUrns) {
		this.schemasProvided = true;
		this.schemasValid = schemaUrns != null && schemaUrns.size() == 1
				&& ScimGroupSchema.URN.equals(schemaUrns.iterator().next());
		super.setSchemaUrns(schemaUrns == null ? List.of() : schemaUrns);
	}

	boolean schemasProvided() {
		return this.schemasProvided;
	}

	boolean schemasValid() {
		return this.schemasValid;
	}

}
