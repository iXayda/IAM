package com.ixayda.iam.scim.internal;

import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.messages.ErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(basePackageClasses = ScimMetadataController.class)
final class ScimExceptionHandler {

	@ExceptionHandler(ScimException.class)
	ResponseEntity<ErrorResponse> handle(ScimException exception) {
		ErrorResponse error = exception.getScimError();
		return ResponseEntity.status(error.getStatus()).contentType(ScimMediaTypes.SCIM_JSON).body(error);
	}

}
