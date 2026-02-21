/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.security.policy;

import java.util.Objects;

/**
 * Represents a network endpoint for egress policy allowlisting.
 * Endpoints specify the host, port, protocol, and purpose for allowed connections.
 *
 * <p>Example usage:
 * <pre>
 * Endpoint anthropic = Endpoint.builder()
 *     .host("api.anthropic.com")
 *     .port(443)
 *     .protocol("https")
 *     .purpose("Claude API")
 *     .requireTlsVerification(true)
 *     .build();
 * </pre>
 */
public final class Endpoint {

	/** Default HTTPS port */
	public static final int DEFAULT_HTTPS_PORT = 443;

	/** Default HTTP port */
	public static final int DEFAULT_HTTP_PORT = 80;

	private final String host;
	private final int port;
	private final String protocol;
	private final String purpose;
	private final boolean requireTlsVerification;

	private Endpoint(Builder builder) {
		this.host = Objects.requireNonNull(builder.host, "host is required");
		this.port = builder.port;
		this.protocol = Objects.requireNonNull(builder.protocol, "protocol is required");
		this.purpose = builder.purpose != null ? builder.purpose : "";
		this.requireTlsVerification = builder.requireTlsVerification;

		if (port < 1 || port > 65535) {
			throw new IllegalArgumentException("Port must be between 1 and 65535: " + port);
		}
		if (!protocol.equals("http") && !protocol.equals("https")) {
			throw new IllegalArgumentException("Protocol must be 'http' or 'https': " + protocol);
		}
	}

	/**
	 * Returns the host for this endpoint.
	 * @return the hostname or IP address
	 */
	public String getHost() {
		return host;
	}

	/**
	 * Returns the port for this endpoint.
	 * @return the port number
	 */
	public int getPort() {
		return port;
	}

	/**
	 * Returns the protocol for this endpoint.
	 * @return "http" or "https"
	 */
	public String getProtocol() {
		return protocol;
	}

	/**
	 * Returns the purpose description for this endpoint.
	 * @return the purpose or empty string
	 */
	public String getPurpose() {
		return purpose;
	}

	/**
	 * Returns whether TLS certificate verification is required.
	 * @return true if TLS verification is required
	 */
	public boolean requiresTlsVerification() {
		return requireTlsVerification;
	}

	/**
	 * Checks if this endpoint matches a request destination.
	 * Matching is performed on normalized host (case-insensitive), port, and protocol.
	 *
	 * @param requestHost the request host
	 * @param requestPort the request port
	 * @param requestProtocol the request protocol
	 * @return true if this endpoint matches
	 */
	public boolean matches(String requestHost, int requestPort, String requestProtocol) {
		if (requestHost == null || requestProtocol == null) {
			return false;
		}
		return host.equalsIgnoreCase(requestHost) &&
			port == requestPort &&
			protocol.equalsIgnoreCase(requestProtocol);
	}

	/**
	 * Creates a new builder for constructing endpoints.
	 * @return a new builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates an endpoint for a standard HTTPS API.
	 *
	 * @param host the hostname
	 * @param purpose the purpose description
	 * @return an HTTPS endpoint on port 443 with TLS verification required
	 */
	public static Endpoint https(String host, String purpose) {
		return builder()
			.host(host)
			.port(DEFAULT_HTTPS_PORT)
			.protocol("https")
			.purpose(purpose)
			.requireTlsVerification(true)
			.build();
	}

	/**
	 * Creates an endpoint for localhost HTTP (e.g., local model servers).
	 *
	 * @param port the port number
	 * @param purpose the purpose description
	 * @return an HTTP endpoint on localhost
	 */
	public static Endpoint localhost(int port, String purpose) {
		return builder()
			.host("localhost")
			.port(port)
			.protocol("http")
			.purpose(purpose)
			.requireTlsVerification(false)
			.build();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof Endpoint)) {
			return false;
		}
		Endpoint other = (Endpoint) obj;
		return host.equalsIgnoreCase(other.host) &&
			port == other.port &&
			protocol.equalsIgnoreCase(other.protocol);
	}

	@Override
	public int hashCode() {
		return Objects.hash(host.toLowerCase(), port, protocol.toLowerCase());
	}

	@Override
	public String toString() {
		return String.format("%s://%s:%d (%s)", protocol, host, port, purpose);
	}

	/**
	 * Builder for creating endpoints.
	 */
	public static final class Builder {
		private String host;
		private int port = DEFAULT_HTTPS_PORT;
		private String protocol = "https";
		private String purpose;
		private boolean requireTlsVerification = true;

		private Builder() {
		}

		public Builder host(String host) {
			this.host = host;
			return this;
		}

		public Builder port(int port) {
			this.port = port;
			return this;
		}

		public Builder protocol(String protocol) {
			this.protocol = protocol;
			return this;
		}

		public Builder purpose(String purpose) {
			this.purpose = purpose;
			return this;
		}

		public Builder requireTlsVerification(boolean require) {
			this.requireTlsVerification = require;
			return this;
		}

		public Endpoint build() {
			return new Endpoint(this);
		}
	}
}
