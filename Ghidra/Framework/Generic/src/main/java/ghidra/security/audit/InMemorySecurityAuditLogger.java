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
package ghidra.security.audit;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Thread-safe in-memory implementation of {@link SecurityAuditLogger}.
 * Suitable for testing and single-session use. For production deployments,
 * use a persistent implementation backed by a database or append-only log file.
 *
 * <p>This implementation:
 * <ul>
 *   <li>Stores events in memory with configurable capacity</li>
 *   <li>Supports concurrent read/write access</li>
 *   <li>Dispatches alerts synchronously to registered listeners</li>
 *   <li>Provides efficient query execution with in-memory filtering</li>
 * </ul>
 */
public class InMemorySecurityAuditLogger implements SecurityAuditLogger {

	private static final int DEFAULT_MAX_EVENTS = 10000;
	private static final int DEFAULT_MAX_VIOLATIONS = 1000;

	private final int maxEvents;
	private final int maxViolations;

	private final List<SecurityAuditEvent> events;
	private final List<ViolationIncident> violations;
	private final List<Consumer<SecurityAuditEvent>> alertListeners;
	private final ReadWriteLock lock;

	/**
	 * Creates a logger with default capacity limits.
	 */
	public InMemorySecurityAuditLogger() {
		this(DEFAULT_MAX_EVENTS, DEFAULT_MAX_VIOLATIONS);
	}

	/**
	 * Creates a logger with specified capacity limits.
	 * When capacity is exceeded, oldest entries are removed.
	 *
	 * @param maxEvents maximum number of events to retain
	 * @param maxViolations maximum number of violations to retain
	 */
	public InMemorySecurityAuditLogger(int maxEvents, int maxViolations) {
		this.maxEvents = maxEvents;
		this.maxViolations = maxViolations;
		this.events = new ArrayList<>();
		this.violations = new ArrayList<>();
		this.alertListeners = new CopyOnWriteArrayList<>();
		this.lock = new ReentrantReadWriteLock();
	}

	@Override
	public void log(SecurityAuditEvent event) {
		Objects.requireNonNull(event, "event must not be null");

		lock.writeLock().lock();
		try {
			events.add(event);
			trimIfNeeded(events, maxEvents);
		}
		finally {
			lock.writeLock().unlock();
		}

		// Dispatch alerts outside the lock
		if (event.getEventType().requiresAlert()) {
			dispatchAlert(event);
		}
	}

	@Override
	public void recordViolation(ViolationIncident incident) {
		Objects.requireNonNull(incident, "incident must not be null");

		// Log the underlying event first
		log(incident.getEvent());

		lock.writeLock().lock();
		try {
			violations.add(incident);
			trimIfNeeded(violations, maxViolations);
		}
		finally {
			lock.writeLock().unlock();
		}
	}

	@Override
	public List<SecurityAuditEvent> queryEvents(AuditQuery query) {
		Objects.requireNonNull(query, "query must not be null");

		lock.readLock().lock();
		try {
			return events.stream()
				.filter(query::matches)
				.sorted(Comparator.comparing(SecurityAuditEvent::getTimestamp).reversed())
				.skip(query.getOffset())
				.limit(query.getLimit())
				.collect(Collectors.toList());
		}
		finally {
			lock.readLock().unlock();
		}
	}

	@Override
	public List<ViolationIncident> queryViolations(AuditQuery query) {
		Objects.requireNonNull(query, "query must not be null");

		lock.readLock().lock();
		try {
			return violations.stream()
				.filter(v -> query.matches(v.getEvent()))
				.sorted(Comparator.comparing(ViolationIncident::getTimestamp).reversed())
				.skip(query.getOffset())
				.limit(query.getLimit())
				.collect(Collectors.toList());
		}
		finally {
			lock.readLock().unlock();
		}
	}

	@Override
	public long getEventCount() {
		lock.readLock().lock();
		try {
			return events.size();
		}
		finally {
			lock.readLock().unlock();
		}
	}

	@Override
	public long getViolationCount() {
		lock.readLock().lock();
		try {
			return violations.size();
		}
		finally {
			lock.readLock().unlock();
		}
	}

	@Override
	public void addAlertListener(Consumer<SecurityAuditEvent> listener) {
		Objects.requireNonNull(listener, "listener must not be null");
		alertListeners.add(listener);
	}

	@Override
	public void removeAlertListener(Consumer<SecurityAuditEvent> listener) {
		alertListeners.remove(listener);
	}

	/**
	 * Returns all events currently stored.
	 * @return unmodifiable list of events
	 */
	public List<SecurityAuditEvent> getAllEvents() {
		lock.readLock().lock();
		try {
			return Collections.unmodifiableList(new ArrayList<>(events));
		}
		finally {
			lock.readLock().unlock();
		}
	}

	/**
	 * Returns all violations currently stored.
	 * @return unmodifiable list of violations
	 */
	public List<ViolationIncident> getAllViolations() {
		lock.readLock().lock();
		try {
			return Collections.unmodifiableList(new ArrayList<>(violations));
		}
		finally {
			lock.readLock().unlock();
		}
	}

	/**
	 * Clears all stored events and violations.
	 * Primarily for testing purposes.
	 */
	public void clear() {
		lock.writeLock().lock();
		try {
			events.clear();
			violations.clear();
		}
		finally {
			lock.writeLock().unlock();
		}
	}

	/**
	 * Returns counts grouped by event type.
	 * @return map of event type to count
	 */
	public Map<SecurityAuditEventType, Long> getEventCountsByType() {
		lock.readLock().lock();
		try {
			return events.stream()
				.collect(Collectors.groupingBy(
					SecurityAuditEvent::getEventType,
					Collectors.counting()));
		}
		finally {
			lock.readLock().unlock();
		}
	}

	/**
	 * Returns counts grouped by severity.
	 * @return map of severity to count
	 */
	public Map<Severity, Long> getEventCountsBySeverity() {
		lock.readLock().lock();
		try {
			return events.stream()
				.collect(Collectors.groupingBy(
					SecurityAuditEvent::getSeverity,
					Collectors.counting()));
		}
		finally {
			lock.readLock().unlock();
		}
	}

	/**
	 * Returns counts grouped by principal.
	 * @return map of principal to count
	 */
	public Map<String, Long> getEventCountsByPrincipal() {
		lock.readLock().lock();
		try {
			return events.stream()
				.collect(Collectors.groupingBy(
					SecurityAuditEvent::getPrincipal,
					Collectors.counting()));
		}
		finally {
			lock.readLock().unlock();
		}
	}

	private void trimIfNeeded(List<?> list, int maxSize) {
		while (list.size() > maxSize) {
			list.remove(0);
		}
	}

	private void dispatchAlert(SecurityAuditEvent event) {
		for (Consumer<SecurityAuditEvent> listener : alertListeners) {
			try {
				listener.accept(event);
			}
			catch (Exception e) {
				// Log but don't propagate listener exceptions
				System.err.println("Alert listener threw exception: " + e.getMessage());
			}
		}
	}
}
