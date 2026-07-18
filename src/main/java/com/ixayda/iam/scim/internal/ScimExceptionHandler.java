package com.ixayda.iam.scim.internal;

import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.messages.ErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import tools.jackson.databind.exc.MismatchedInputException;

@RestControllerAdvice(basePackageClasses = ScimMetadataController.class)
final class ScimExceptionHandler {

	@ExceptionHandler(ScimException.class)
	ResponseEntity<ErrorResponse> handle(ScimException exception) {
		ErrorResponse error = exception.getScimError();
		return ResponseEntity.status(error.getStatus()).contentType(ScimMediaTypes.SCIM_JSON).body(error);
	}

	@ExceptionHandler(HttpMessageNotReadableException.class)
	ResponseEntity<ErrorResponse> handleUnreadableRequest(HttpMessageNotReadableException exception) {
		if (exception.getCause() instanceof MismatchedInputException) {
			return handle(BadRequestException.invalidValue(
					"The SCIM request contains a value that is incompatible with its attribute type."));
		}
		return handle(BadRequestException.invalidSyntax("The SCIM request body is invalid."));
	}

}
