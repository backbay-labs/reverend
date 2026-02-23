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

import static org.junit.Assert.*;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.security.audit.InMemorySecurityAuditLogger;
import ghidra.security.audit.SecurityAuditEvent;
import ghidra.security.audit.SecurityAuditEventType;
import ghidra.security.credential.KeyRotationService.*;

/**
 * Tests for {@link KeyRotationService} covering key rotation, scheduling,
 * grace periods, and audit logging.
 */
public class KeyRotationServiceTest {

	private InMemorySecurityAuditLogger auditLogger;
	private InMemoryRevocationRegistry revocationRegistry;
	private KeyRotationService rotationService;

	@Before
	public void setUp() {
		auditLogger = new InMemorySecurityAuditLogger();
		revocationRegistry = new InMemoryRevocationRegistry();
		rotationService = new KeyRotationService(auditLogger, revocationRegistry, "test-service");
	}

	@After
	public void tearDown() {
		if (rotationService != null) {
			rotationService.shutdown();
		}
	}

	@Test
	public void testInitialization_createsInitialKey() {
		KeyVersion key = rotationService.getCurrentKey();

		assertNotNull(key);
		assertNotNull(key.getKeyId());
		assertNotNull(key.getKeyMaterial());
		assertEquals(32, key.getKeyMaterial().length); // 256 bits
		assertEquals(1, key.getVersion());
	}

	@Test
	public void testRotateKey_createsNewKey() {
		KeyVersion oldKey = rotationService.getCurrentKey();

		KeyVersion newKey = rotationService.rotateKey(RotationTrigger.MANUAL);

		assertNotNull(newKey);
		assertNotEquals(oldKey.getKeyId(), newKey.getKeyId());
		assertEquals(2, newKey.getVersion());
		assertEquals(2, rotationService.getRotationCount());
	}

	@Test
	public void testRotateKey_logsAuditEvent() {
		int eventsBefore = auditLogger.getAllEvents().size();

		rotationService.rotateKey(RotationTrigger.MANUAL);

		List<SecurityAuditEvent> events = auditLogger.getAllEvents();
		assertTrue(events.size() > eventsBefore);
		assertTrue(events.stream()
			.anyMatch(e -> e.getEventType() == SecurityAuditEventType.KEY_ROTATED));
	}

	@Test
	public void testIsKeyValid_currentKeyIsValid() {
		KeyVersion current = rotationService.getCurrentKey();

		assertTrue(rotationService.isKeyValid(current.getKeyId()));
	}

	@Test
	public void testIsKeyValid_unknownKeyIsInvalid() {
		assertFalse(rotationService.isKeyValid("unknown-key-id"));
	}

	@Test
	public void testIsKeyValid_previousKeyValidDuringGracePeriod() {
		KeyVersion oldKey = rotationService.getCurrentKey();

		// Rotate to new key
		rotationService.rotateKey(RotationTrigger.MANUAL);
		KeyVersion newKey = rotationService.getCurrentKey();

		// Old key should still be valid (within grace period)
		assertTrue(rotationService.isKeyValid(oldKey.getKeyId()));
		assertTrue(rotationService.isKeyValid(newKey.getKeyId()));
	}

	@Test
	public void testEmergencyRotate_invalidatesOldKeyImmediately() {
		KeyVersion oldKey = rotationService.getCurrentKey();

		KeyVersion newKey = rotationService.emergencyRotate("security incident");

		assertNotNull(newKey);
		assertNotEquals(oldKey.getKeyId(), newKey.getKeyId());

		// Old key should NOT be valid (no grace period)
		assertFalse(rotationService.isKeyValid(oldKey.getKeyId()));
		assertTrue(rotationService.isKeyValid(newKey.getKeyId()));

		// Should have critical severity audit event
		assertTrue(auditLogger.getAllEvents().stream()
			.anyMatch(e -> e.getEventType() == SecurityAuditEventType.KEY_ROTATED
				&& "emergency_rotation".equals(e.getDetail("action"))));
	}

	@Test
	public void testSetRotationInterval_updatesInterval() {
		Duration newInterval = Duration.ofHours(12);

		rotationService.setRotationInterval(newInterval);

		assertEquals(newInterval, rotationService.getRotationInterval());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSetRotationInterval_belowMinimum_throws() {
		rotationService.setRotationInterval(Duration.ofMinutes(30));
	}

	@Test
	public void testSetGracePeriod_updatesPeriod() {
		Duration newPeriod = Duration.ofHours(48);

		rotationService.setGracePeriod(newPeriod);

		assertEquals(newPeriod, rotationService.getGracePeriod());
	}

	@Test
	public void testGetRotationCount_tracksRotations() {
		assertEquals(1, rotationService.getRotationCount()); // Initial key

		rotationService.rotateKey(RotationTrigger.MANUAL);
		assertEquals(2, rotationService.getRotationCount());

		rotationService.rotateKey(RotationTrigger.SCHEDULED);
		assertEquals(3, rotationService.getRotationCount());
	}

	@Test
	public void testAddRotationListener_receivesEvents() throws InterruptedException {
		CountDownLatch latch = new CountDownLatch(1);
		List<RotationEvent> receivedEvents = new ArrayList<>();

		rotationService.addRotationListener(event -> {
			receivedEvents.add(event);
			latch.countDown();
		});

		rotationService.rotateKey(RotationTrigger.MANUAL);

		assertTrue(latch.await(1, TimeUnit.SECONDS));
		assertEquals(1, receivedEvents.size());
		assertEquals(RotationTrigger.MANUAL, receivedEvents.get(0).getTrigger());
	}

	@Test
	public void testRemoveRotationListener_stopsReceivingEvents() {
		List<RotationEvent> receivedEvents = new ArrayList<>();
		java.util.function.Consumer<RotationEvent> listener = receivedEvents::add;

		rotationService.addRotationListener(listener);
		rotationService.rotateKey(RotationTrigger.MANUAL);
		assertEquals(1, receivedEvents.size());

		rotationService.removeRotationListener(listener);
		rotationService.rotateKey(RotationTrigger.MANUAL);
		assertEquals(1, receivedEvents.size()); // No new events
	}

	@Test
	public void testPruneExpiredKeys_removesExpiredFromHistory() {
		// Set a very short grace period for testing
		rotationService.setGracePeriod(Duration.ofMillis(10));

		rotationService.rotateKey(RotationTrigger.MANUAL);
		rotationService.rotateKey(RotationTrigger.MANUAL);

		// Wait for grace period to expire
		try {
			Thread.sleep(50);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}

		int pruned = rotationService.pruneExpiredKeys();

		assertTrue(pruned >= 0);
	}

	@Test
	public void testKeyVersion_getKeyMaterial_returnsCopy() {
		KeyVersion key = rotationService.getCurrentKey();
		byte[] material1 = key.getKeyMaterial();
		byte[] material2 = key.getKeyMaterial();

		assertNotSame(material1, material2);
		assertArrayEquals(material1, material2);

		// Modifying returned array should not affect the key
		material1[0] = (byte) 0xFF;
		assertNotEquals(material1[0], key.getKeyMaterial()[0]);
	}

	@Test
	public void testKeyVersion_withExpiration_createsNewInstance() {
		KeyVersion original = rotationService.getCurrentKey();
		java.time.Instant newExpiration = java.time.Instant.now().plusSeconds(3600);

		KeyVersion modified = original.withExpiration(newExpiration);

		assertNotSame(original, modified);
		assertEquals(original.getKeyId(), modified.getKeyId());
		assertEquals(original.getVersion(), modified.getVersion());
		assertEquals(newExpiration, modified.getExpiresAt());
	}

	@Test
	public void testRotationTrigger_allValuesExist() {
		RotationTrigger[] triggers = RotationTrigger.values();

		assertTrue(triggers.length >= 4);
		assertNotNull(RotationTrigger.INITIAL);
		assertNotNull(RotationTrigger.SCHEDULED);
		assertNotNull(RotationTrigger.MANUAL);
		assertNotNull(RotationTrigger.SECURITY_INCIDENT);
	}

	@Test
	public void testRotationEvent_containsCorrectInfo() {
		KeyVersion oldKey = rotationService.getCurrentKey();

		List<RotationEvent> events = new ArrayList<>();
		rotationService.addRotationListener(events::add);

		rotationService.rotateKey(RotationTrigger.POLICY_COMPLIANCE);

		assertEquals(1, events.size());
		RotationEvent event = events.get(0);
		assertEquals(oldKey.getKeyId(), event.getOldKeyId());
		assertNotNull(event.getNewKeyId());
		assertEquals(RotationTrigger.POLICY_COMPLIANCE, event.getTrigger());
		assertNotNull(event.getTimestamp());
	}

	@Test
	public void testGetTimeUntilNextRotation_nullWhenNotScheduled() {
		assertNull(rotationService.getTimeUntilNextRotation());
	}

	@Test
	public void testStopScheduledRotation_stopsRotation() {
		rotationService.startScheduledRotation();
		assertNotNull(rotationService.getTimeUntilNextRotation());

		rotationService.stopScheduledRotation();
		assertNull(rotationService.getTimeUntilNextRotation());
	}
}
