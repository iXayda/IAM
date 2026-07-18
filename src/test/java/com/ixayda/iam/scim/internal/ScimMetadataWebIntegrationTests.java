package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class ScimMetadataWebIntegrationTests extends ApplicationIntegrationTest {

	private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json");

	private static final String LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

	private static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

	private static final JsonMapper JSON = JsonMapper.builder().build();

	private final HttpClient httpClient = HttpClient.newHttpClient();

	@LocalServerPort
	private int port;

	@Autowired
	private MockMvc mockMvc;

	@Test
	void servesDiscoveryThroughTheRealHttpStack() throws Exception {
		URI endpoint = URI.create("http://127.0.0.1:" + this.port + "/scim/v2/ServiceProviderConfig");
		HttpRequest request = HttpRequest.newBuilder(endpoint)
			.header(HttpHeaders.ACCEPT, SCIM_JSON.toString())
			.GET()
			.build();

		HttpResponse<String> response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());

		assertThat(response.statusCode()).isEqualTo(200);
		assertThat(response.headers().firstValue(HttpHeaders.CONTENT_TYPE)).hasValue(SCIM_JSON.toString());
		assertThat(response.headers().firstValue(HttpHeaders.CONTENT_LOCATION))
			.hasValue("https://scim.example.test/scim/v2/ServiceProviderConfig");
		JsonNode body = JSON.readTree(response.body());
		assertThat(body.get("patch").get("supported").booleanValue()).isFalse();
		assertThat(body.get("meta").get("location").stringValue())
			.isEqualTo("https://scim.example.test/scim/v2/ServiceProviderConfig");
	}

	@Test
	void exposesTheImplementedServiceProviderCapabilities() throws Exception {
		this.mockMvc.perform(get("/scim/v2/ServiceProviderConfig").accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(header().string(HttpHeaders.CONTENT_LOCATION,
					"https://scim.example.test/scim/v2/ServiceProviderConfig"))
			.andExpect(jsonPath("$.schemas[0]")
				.value("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"))
			.andExpect(jsonPath("$.patch.supported").value(false))
			.andExpect(jsonPath("$.bulk.supported").value(false))
			.andExpect(jsonPath("$.bulk.maxOperations").value(0))
			.andExpect(jsonPath("$.bulk.maxPayloadSize").value(0))
			.andExpect(jsonPath("$.filter.supported").value(false))
			.andExpect(jsonPath("$.filter.maxResults").value(0))
			.andExpect(jsonPath("$.changePassword.supported").value(false))
			.andExpect(jsonPath("$.sort.supported").value(false))
			.andExpect(jsonPath("$.etag.supported").value(false))
			.andExpect(jsonPath("$.authenticationSchemes", hasSize(0)))
			.andExpect(jsonPath("$.meta.resourceType").value("ServiceProviderConfig"))
			.andExpect(jsonPath("$.meta.location").value("https://scim.example.test/scim/v2/ServiceProviderConfig"))
			.andExpect(jsonPath("$.id").doesNotExist())
			.andExpect(jsonPath("$.pagination").doesNotExist());
	}

	@Test
	void exposesEmptySchemaAndResourceTypeCatalogs() throws Exception {
		assertEmptyCatalog("/scim/v2/Schemas");
		assertEmptyCatalog("/scim/v2/ResourceTypes");
	}

	@Test
	void supportsApplicationJsonForDiscoveryClients() throws Exception {
		this.mockMvc.perform(get("/scim/v2/Schemas").accept(MediaType.APPLICATION_JSON))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
			.andExpect(jsonPath("$.totalResults").value(0));
	}

	@Test
	void ignoresUnsupportedNonFilterDiscoveryParameters() throws Exception {
		this.mockMvc.perform(get("/scim/v2/ResourceTypes?count=1&sortBy=name").accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.totalResults").value(0))
			.andExpect(header().string(HttpHeaders.CONTENT_LOCATION,
					"https://scim.example.test/scim/v2/ResourceTypes"));
	}

	@Test
	void rejectsFiltersWithoutReflectingTheirValue() throws Exception {
		this.mockMvc.perform(get("/scim/v2/Schemas?filter=userName%20eq%20%22secret%22").accept(SCIM_JSON))
			.andExpect(status().isForbidden())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
			.andExpect(jsonPath("$.status").value("403"))
			.andExpect(jsonPath("$.detail").value("Filtering SCIM discovery resources is not supported."))
			.andExpect(content().string(org.hamcrest.Matchers.not(containsString("secret"))));
	}

	@Test
	void returnsScimErrorsForUnknownCatalogItems() throws Exception {
		assertNotFound("/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User");
		assertNotFound(URI.create("/scim/v2/ResourceTypes/urn%3Aietf%3Aparams%3Ascim%3Aschemas%3Acore%3A2.0%3AUser"));
	}

	@Test
	void keepsProvisioningAndWriteRequestsClosed() throws Exception {
		this.mockMvc.perform(get("/scim/v2/Users").accept(SCIM_JSON)).andExpect(status().isForbidden())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
			.andExpect(jsonPath("$.status").value("403"));

		this.mockMvc.perform(post("/scim/v2/ServiceProviderConfig").accept(SCIM_JSON))
			.andExpect(status().isForbidden())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.status").value("403"));
	}

	@Test
	void doesNotCreateAnHttpSessionForDiscovery() throws Exception {
		MvcResult result = this.mockMvc.perform(get("/scim/v2/ServiceProviderConfig").accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
			.andReturn();

		assertThat(result.getRequest().getSession(false)).isNull();
	}

	private void assertEmptyCatalog(String path) throws Exception {
		this.mockMvc.perform(get(path).accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(header().string(HttpHeaders.CONTENT_LOCATION, "https://scim.example.test" + path))
			.andExpect(jsonPath("$.schemas[0]").value(LIST_RESPONSE_SCHEMA))
			.andExpect(jsonPath("$.totalResults").value(0))
			.andExpect(jsonPath("$.Resources", hasSize(0)))
			.andExpect(jsonPath("$.startIndex").doesNotExist())
			.andExpect(jsonPath("$.itemsPerPage").doesNotExist());
	}

	private void assertNotFound(String path) throws Exception {
		assertNotFound(URI.create(path));
	}

	private void assertNotFound(URI path) throws Exception {
		this.mockMvc.perform(get(path).accept(SCIM_JSON))
			.andExpect(status().isNotFound())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
			.andExpect(jsonPath("$.status").value("404"));
	}

}
