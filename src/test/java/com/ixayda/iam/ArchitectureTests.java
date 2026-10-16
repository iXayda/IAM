package com.ixayda.iam;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.library.dependencies.SliceAssignment;
import com.tngtech.archunit.library.dependencies.SliceIdentifier;

import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.core.domain.JavaClass.Predicates.equivalentTo;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.Architectures.layeredArchitecture;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

class ArchitectureTests {

	private static final JavaClasses APPLICATION_CLASSES = new ClassFileImporter()
			.withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
			.importPackagesOf(IamApplication.class);

	@Test
	void respectsLayerDependencies() {
		layeredArchitecture().consideringAllDependencies()
				.ensureAllClassesAreContainedInArchitectureIgnoring(equivalentTo(IamApplication.class))
				.optionalLayer("Controller").definedBy("com.ixayda.iam.controller..")
				.layer("Security").definedBy("com.ixayda.iam.security..")
				.optionalLayer("DTO").definedBy("com.ixayda.iam.dto..")
				.layer("Service").definedBy("com.ixayda.iam.service..")
				.layer("Repository").definedBy("com.ixayda.iam.repository..")
				.layer("Model").definedBy("com.ixayda.iam.model..")
				.layer("Credential").definedBy("com.ixayda.iam.credential..")
				.whereLayer("Controller").mayNotBeAccessedByAnyLayer()
				.whereLayer("DTO").mayOnlyBeAccessedByLayers("Controller")
				.whereLayer("Service").mayOnlyBeAccessedByLayers("Controller", "Security")
				.whereLayer("Security").mayOnlyBeAccessedByLayers("Controller")
				.whereLayer("Repository").mayOnlyBeAccessedByLayers("Service")
				.whereLayer("Model").mayOnlyBeAccessedByLayers("Controller", "DTO", "Service", "Repository", "Security")
				.whereLayer("Credential").mayOnlyBeAccessedByLayers("Service")
				.check(APPLICATION_CLASSES);
	}

	@Test
	void topLevelTypesDoNotFormDependencyCycles() {
		slices().assignedFrom(new SliceAssignment() {
			@Override
			public SliceIdentifier getIdentifierOf(JavaClass javaClass) {
				// Nested implementation types belong to the same component as their enclosing type.
				return SliceIdentifier.of(javaClass.getName().split("\\$", 2)[0]);
			}

			@Override
			public String getDescription() {
				return "top-level application types";
			}
		}).should().beFreeOfCycles().check(APPLICATION_CLASSES);
	}

	@Test
	void modelsDoNotDependOnSpringOrDatabaseApis() {
		noClasses().that().resideInAPackage("com.ixayda.iam.model..")
				.should().dependOnClassesThat()
				.resideInAnyPackage("org.springframework..", "java.sql..", "javax.sql..")
				.check(APPLICATION_CLASSES);
	}

}
