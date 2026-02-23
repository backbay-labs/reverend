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
package ghidra.security.credential;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import ghidra.security.audit.*;
import ghidra.security.credential.RevocationRegistry.RevocationReason;

/**
 * Service for automated key rotation with configurable schedules.
 * Manages cryptographic keys used for token signing and provides
 * automated rotation with audit trails.
 *
 * <p>The service provides:
 * <ul>
 *   <li>Scheduled automatic rotation (default: every 30 days)</li>
 *   <li>Manual rotation on demand (e.g., security incident)</li>
 *   <li>Grace period for key transitions</li>
 *   <li>Audit logging of all rotation events</li>
 *   <li>Hooks for post-rotation actions (e.g., token revocation)</li>
 * </ul>
 *
 * <p>Based on the agent-runtime-security-spec key rotation requirements.
 */
public class KeyRotationService {

	/** Default rotation interval: 30 days */
	public static final Duration DEFAULT_ROTATION_INTERVAL = Duration.ofDays(30);

	/** Default grace period: 24 hours */
	public static final Duration DEFAULT_GRACE_PERIOD = Duration.ofHours(24);

	/** Minimum rotation interval: 1 hour */
	public static final Duration MIN_ROTATION_INTERVAL = Duration.ofHours(1);

	private final SecurityAuditLogger auditLogger;
	private final RevocationRegistry revocationRegistry;
	private final String serviceId;
	private final SecureRandom secureRandom;

	private final AtomicReference<KeyVersion> currentKey = new AtomicReference<>();
	private final ConcurrentHashMap<String, KeyVersion> keyHistory = new ConcurrentHashMap<>();
	private final List<Consumer<RotationEvent>> rotationListeners =
		new CopyOnWriteArrayList<>();

	private final ScheduledExecutorService scheduler;
	private ScheduledFuture<?> scheduledRotation;
	private Duration rotationInterval = DEFAULT_ROTATION_INTERVAL;
	private Duration gracePeriod = DEFAULT_GRACE_PERIOD;
	private final AtomicInteger rotationCount = new AtomicInteger(0);

	/**
	 * Creates a new key rotation service.
	 *
	 * @param auditLogger the audit logger for compliance
	 * @param revocationRegistry the revocation registry for invalidating tokens
	 * @param serviceId identifier for this service instance
	 */
	public KeyRotationService(SecurityAuditLogger auditLogger,
			RevocationRegistry revocationRegistry, String serviceId) {
		this.auditLogger = Objects.requireNonNull(auditLogger);
		this.revocationRegistry = Objects.requireNonNull(revocationRegistry);
		this.serviceId = Objects.requireNonNull(serviceId);
		this.secureRandom = new SecureRandom();
		this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "KeyRotationService-" + serviceId);
			t.setDaemon(true);
			return t;
		});

		// Initialize with a key
		rotateKey(RotationTrigger.INITIAL);
	}

	/**
	 * Returns the current active key version.
	 *
	 * @return the current key version
	 */
	public KeyVersion getCurrentKey() {
		return currentKey.get();
	}

	/**
	 * Checks if a key version is still valid (current or within grace period).
	 *
	 * @param keyId the key ID to check
	 * @return true if the key is valid
	 */
	public boolean isKeyValid(String keyId) {
		KeyVersion current = currentKey.get();
		if (current != null && current.getKeyId().equals(keyId)) {
			return true;
		}
		// Check if within grace period of a previous key
		KeyVersion historical = keyHistory.get(keyId);
		if (historical != null && historical.isWithinGracePeriod()) {
			return true;
		}
		return false;
	}

	/**
	 * Performs an immediate key rotation.
	 *
	 * @param trigger the reason for rotation
	 * @return the new key version
	 */
	public KeyVersion rotateKey(RotationTrigger trigger) {
		KeyVersion oldKey = currentKey.get();
		Instant now = Instant.now();

		// Generate new key
		String newKeyId = generateKeyId();
		byte[] newKeyMaterial = generateKeyMaterial();
		KeyVersion newKey = new KeyVersion(
			newKeyId,
			newKeyMaterial,
			now,
			now.plus(gracePeriod),
			rotationCount.incrementAndGet()
		);

		// Atomic swap
		currentKey.set(newKey);

		// Move old key to history with grace period
		if (oldKey != null) {
			keyHistory.put(oldKey.getKeyId(), oldKey.withExpiration(now.plus(gracePeriod)));
		}

		// Log rotation
		logKeyRotation(trigger, oldKey, newKey);

		// Notify listeners
		RotationEvent event = new RotationEvent(
			oldKey != null ? oldKey.getKeyId() : null,
			newKey.getKeyId(),
			trigger,
			now
		);
		for (Consumer<RotationEvent> listener : rotationListeners) {
			try {
				listener.accept(event);
			}
			catch (Exception e) {
				// Log but don't fail rotation
				auditLogger.log(SecurityAuditEvent.builder()
					.eventType(SecurityAuditEventType.KEY_ROTATION_FAILED)
					.severity(Severity.WARNING)
					.principal(serviceId)
					.detail("error", "Rotation listener failed: " + e.getMessage())
					.build());
			}
		}

		return newKey;
	}

	/**
	 * Performs emergency rotation and revokes all tokens issued with the old key.
	 *
	 * @param reason the reason for emergency rotation
	 * @return the new key version
	 */
	public KeyVersion emergencyRotate(String reason) {
		KeyVersion oldKey = currentKey.get();
		KeyVersion newKey = rotateKey(RotationTrigger.SECURITY_INCIDENT);

		// Immediately expire the old key (no grace period)
		if (oldKey != null) {
			keyHistory.remove(oldKey.getKeyId());

			auditLogger.log(SecurityAuditEvent.builder()
				.eventType(SecurityAuditEventType.KEY_ROTATED)
				.severity(Severity.CRITICAL)
				.principal(serviceId)
				.detail("action", "emergency_rotation")
				.detail("reason", reason)
				.detail("old_key_id", oldKey.getKeyId())
				.detail("new_key_id", newKey.getKeyId())
				.detail("grace_period", "none")
				.build());
		}

		return newKey;
	}

	/**
	 * Starts automatic rotation on the configured schedule.
	 */
	public void startScheduledRotation() {
		stopScheduledRotation();
		scheduledRotation = scheduler.scheduleAtFixedRate(
			() -> rotateKey(RotationTrigger.SCHEDULED),
			rotationInterval.toMillis(),
			rotationInterval.toMillis(),
			TimeUnit.MILLISECONDS
		);

		auditLogger.log(SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.SESSION_STARTED)
			.principal(serviceId)
			.detail("action", "scheduled_rotation_started")
			.detail("interval_hours", String.valueOf(rotationInterval.toHours()))
			.build());
	}

	/**
	 * Stops automatic rotation.
	 */
	public void stopScheduledRotation() {
		if (scheduledRotation != null) {
			scheduledRotation.cancel(false);
			scheduledRotation = null;
		}
	}

	/**
	 * Configures the rotation interval.
	 *
	 * @param interval the new rotation interval
	 * @throws IllegalArgumentException if interval is below minimum
	 */
	public void setRotationInterval(Duration interval) {
		if (interval.compareTo(MIN_ROTATION_INTERVAL) < 0) {
			throw new IllegalArgumentException(
				"Rotation interval must be at least " + MIN_ROTATION_INTERVAL.toHours() + " hours");
		}
		this.rotationInterval = interval;

		// Restart scheduled rotation if active
		if (scheduledRotation != null && !scheduledRotation.isCancelled()) {
			startScheduledRotation();
		}
	}

	/**
	 * Configures the grace period for old keys after rotation.
	 *
	 * @param period the grace period
	 */
	public void setGracePeriod(Duration period) {
		this.gracePeriod = Objects.requireNonNull(period);
	}

	/**
	 * Returns the current rotation interval.
	 *
	 * @return the rotation interval
	 */
	public Duration getRotationInterval() {
		return rotationInterval;
	}

	/**
	 * Returns the grace period.
	 *
	 * @return the grace period
	 */
	public Duration getGracePeriod() {
		return gracePeriod;
	}

	/**
	 * Returns the total number of rotations performed.
	 *
	 * @return the rotation count
	 */
	public int getRotationCount() {
		return rotationCount.get();
	}

	/**
	 * Returns the time until the next scheduled rotation, or null if not scheduled.
	 *
	 * @return time until next rotation, or null
	 */
	public Duration getTimeUntilNextRotation() {
		if (scheduledRotation == null || scheduledRotation.isCancelled()) {
			return null;
		}
		long delay = scheduledRotation.getDelay(TimeUnit.MILLISECONDS);
		return delay > 0 ? Duration.ofMillis(delay) : Duration.ZERO;
	}

	/**
	 * Adds a listener for rotation events.
	 *
	 * @param listener the listener to add
	 */
	public void addRotationListener(Consumer<RotationEvent> listener) {
		rotationListeners.add(listener);
	}

	/**
	 * Removes a rotation listener.
	 *
	 * @param listener the listener to remove
	 */
	public void removeRotationListener(Consumer<RotationEvent> listener) {
		rotationListeners.remove(listener);
	}

	/**
	 * Cleans up expired keys from history.
	 *
	 * @return the number of keys removed
	 */
	public int pruneExpiredKeys() {
		int count = 0;
		Instant now = Instant.now();
		Iterator<Map.Entry<String, KeyVersion>> it = keyHistory.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<String, KeyVersion> entry = it.next();
			if (!entry.getValue().isWithinGracePeriod()) {
				it.remove();
				count++;
			}
		}
		return count;
	}

	/**
	 * Shuts down the service.
	 */
	public void shutdown() {
		stopScheduledRotation();
		scheduler.shutdown();
	}

	private String generateKeyId() {
		return "key-" + UUID.randomUUID().toString().substring(0, 8) +
			"-" + Instant.now().getEpochSecond();
	}

	private byte[] generateKeyMaterial() {
		byte[] material = new byte[32]; // 256 bits
		secureRandom.nextBytes(material);
		return material;
	}

	private void logKeyRotation(RotationTrigger trigger, KeyVersion oldKey, KeyVersion newKey) {
		auditLogger.log(SecurityAuditEvent.builder()
			.eventType(SecurityAuditEventType.KEY_ROTATED)
			.principal(serviceId)
			.detail("trigger", trigger.name())
			.detail("old_key_id", oldKey != null ? oldKey.getKeyId() : "none")
			.detail("new_key_id", newKey.getKeyId())
			.detail("rotation_number", String.valueOf(newKey.getVersion()))
			.detail("grace_period_hours", String.valueOf(gracePeriod.toHours()))
			.build());
	}

	/**
	 * Represents a version of a cryptographic key.
	 */
	public static final class KeyVersion {
		private final String keyId;
		private final byte[] keyMaterial;
		private final Instant createdAt;
		private final Instant expiresAt;
		private final int version;

		public KeyVersion(String keyId, byte[] keyMaterial, Instant createdAt,
				Instant expiresAt, int version) {
			this.keyId = keyId;
			this.keyMaterial = Arrays.copyOf(keyMaterial, keyMaterial.length);
			this.createdAt = createdAt;
			this.expiresAt = expiresAt;
			this.version = version;
		}

		public String getKeyId() {
			return keyId;
		}

		public byte[] getKeyMaterial() {
			return Arrays.copyOf(keyMaterial, keyMaterial.length);
		}

		public Instant getCreatedAt() {
			return createdAt;
		}

		public Instant getExpiresAt() {
			return expiresAt;
		}

		public int getVersion() {
			return version;
		}

		public boolean isWithinGracePeriod() {
			return Instant.now().isBefore(expiresAt);
		}

		public KeyVersion withExpiration(Instant newExpiration) {
			return new KeyVersion(keyId, keyMaterial, createdAt, newExpiration, version);
		}

		@Override
		public String toString() {
			return String.format("KeyVersion[id=%s, version=%d, expires=%s]",
				keyId, version, expiresAt);
		}
	}

	/**
	 * Triggers for key rotation.
	 */
	public enum RotationTrigger {
		/** Initial key generation */
		INITIAL,
		/** Scheduled automatic rotation */
		SCHEDULED,
		/** Manual rotation requested */
		MANUAL,
		/** Security incident response */
		SECURITY_INCIDENT,
		/** Policy compliance requirement */
		POLICY_COMPLIANCE
	}

	/**
	 * Event emitted when key rotation occurs.
	 */
	public static final class RotationEvent {
		private final String oldKeyId;
		private final String newKeyId;
		private final RotationTrigger trigger;
		private final Instant timestamp;

		public RotationEvent(String oldKeyId, String newKeyId,
				RotationTrigger trigger, Instant timestamp) {
			this.oldKeyId = oldKeyId;
			this.newKeyId = newKeyId;
			this.trigger = trigger;
			this.timestamp = timestamp;
		}

		public String getOldKeyId() {
			return oldKeyId;
		}

		public String getNewKeyId() {
			return newKeyId;
		}

		public RotationTrigger getTrigger() {
			return trigger;
		}

		public Instant getTimestamp() {
			return timestamp;
		}

		@Override
		public String toString() {
			return String.format("RotationEvent[%s -> %s, trigger=%s, at=%s]",
				oldKeyId, newKeyId, trigger, timestamp);
		}
	}
}
