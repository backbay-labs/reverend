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
package ghidra.reverend.cockpit;

import java.awt.*;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.app.services.GoToService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.reverend.api.v1.EvidenceService;
import ghidra.reverend.api.v1.EvidenceService.Evidence;
import ghidra.reverend.api.v1.EvidenceService.EvidenceType;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

/**
 * Dockable provider for evidence drilldown and facet exploration.
 *
 * <p>This provider shows evidence details organized by type/facet:
 * <ul>
 *   <li>Static analysis evidence (data flow, control flow)</li>
 *   <li>Dynamic trace evidence</li>
 *   <li>Model inference results with confidence</li>
 *   <li>Cross-references and call site evidence</li>
 * </ul>
 *
 * <p>Each evidence card provides jump-to-address actions for navigation.
 */
public class EvidenceDrawerProvider extends ComponentProviderAdapter {

	public static final String TITLE = "Evidence Drawer";
	public static final String OWNER = "ReverendPlugin";

	private static final String KEY_VISIBLE = "evidenceDrawerVisible";
	private static final String KEY_SELECTED_ID = "selectedEvidenceId";
	private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ISO_INSTANT;

	private final EvidenceService evidenceService;

	private Program currentProgram;
	private JPanel mainPanel;
	private JPanel evidenceCardsPanel;
	private JScrollPane scrollPane;
	private JLabel statusLabel;

	private String currentEvidenceId;
	private List<Evidence> currentEvidence = new ArrayList<>();
	private CockpitState.OperationStatus operationStatus = CockpitState.OperationStatus.IDLE;
	private String operationMessage = "";

	/**
	 * Creates a new evidence drawer provider.
	 *
	 * @param tool the plugin tool
	 * @param evidenceService the evidence service
	 */
	public EvidenceDrawerProvider(PluginTool tool, EvidenceService evidenceService) {
		super(tool, TITLE, OWNER);
		this.evidenceService = Objects.requireNonNull(evidenceService,
			"evidenceService cannot be null");

		buildComponent();
		createActions();

		setDefaultWindowPosition(WindowPosition.RIGHT);
		setIcon(Icons.INFO_ICON);
		setHelpLocation(new HelpLocation(OWNER, "EvidenceDrawer"));
		setWindowMenuGroup("Reverend");
	}

	private void buildComponent() {
		mainPanel = new JPanel(new BorderLayout(5, 5));
		mainPanel.setPreferredSize(new Dimension(350, 500));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		// Header
		JPanel headerPanel = new JPanel(new BorderLayout());
		JLabel titleLabel = new JLabel("Evidence Details");
		titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
		headerPanel.add(titleLabel, BorderLayout.WEST);

		// Evidence cards container
		evidenceCardsPanel = new JPanel();
		evidenceCardsPanel.setLayout(new BoxLayout(evidenceCardsPanel, BoxLayout.Y_AXIS));
		scrollPane = new JScrollPane(evidenceCardsPanel);
		scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
		scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

		// Status bar
		statusLabel = new JLabel("No evidence selected");
		statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));

		mainPanel.add(headerPanel, BorderLayout.NORTH);
		mainPanel.add(scrollPane, BorderLayout.CENTER);
		mainPanel.add(statusLabel, BorderLayout.SOUTH);
	}

	private void createActions() {
		DockingAction refreshAction = new DockingAction("Refresh Evidence", OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				refreshEvidence();
			}
		};
		refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON));
		refreshAction.setDescription("Refresh evidence display");
		addLocalAction(refreshAction);

		DockingAction clearAction = new DockingAction("Clear Evidence", OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				clearEvidence();
			}
		};
		clearAction.setPopupMenuData(new MenuData(new String[] { "Clear" }));
		clearAction.setDescription("Clear the evidence display");
		addLocalAction(clearAction);
	}

	/**
	 * Sets the current program for evidence queries.
	 *
	 * @param program the program
	 */
	public void setProgram(Program program) {
		this.currentProgram = program;
		if (currentEvidenceId != null) {
			refreshEvidence();
		}
	}

	/**
	 * Clears the current program reference.
	 */
	public void clearProgram() {
		this.currentProgram = null;
		clearEvidence();
	}

	/**
	 * Shows evidence for a specific evidence ID.
	 *
	 * @param evidenceId the evidence ID to display
	 */
	public void showEvidence(String evidenceId) {
		this.currentEvidenceId = evidenceId;
		refreshEvidence();
	}

	/**
	 * Shows evidence drilldown for a search hit, including static/dynamic provenance overlays.
	 *
	 * @param entry selected search result entry
	 */
	public void showEvidenceForHit(SearchResultEntry entry) {
		if (entry == null) {
			clearEvidence();
			return;
		}

		this.currentEvidenceId = entry.getEvidenceId().orElse(null);
		if (currentEvidenceId == null) {
			displayEvidence(Collections.emptyList(), entry);
			setOperationState(CockpitState.OperationStatus.SUCCESS,
				"Loaded provenance overlay for selected hit");
			statusLabel.setText("Provenance links for selected hit");
			return;
		}

		setOperationState(CockpitState.OperationStatus.LOADING,
			"Loading evidence " + currentEvidenceId);
		Optional<Evidence> evidence = evidenceService.get(currentEvidenceId);
		List<Evidence> allEvidence = new ArrayList<>();
		if (evidence.isPresent()) {
			allEvidence.add(evidence.get());
			allEvidence.addAll(evidenceService.getDerivationChain(currentEvidenceId));
		}
		displayEvidence(allEvidence, entry);
		setOperationState(CockpitState.OperationStatus.SUCCESS,
			"Loaded " + allEvidence.size() + " items");
		statusLabel.setText("Evidence: " + currentEvidenceId);
	}

	/**
	 * Shows evidence for a specific address.
	 *
	 * @param address the address to show evidence for
	 */
	public void showEvidenceForAddress(Address address) {
		if (currentProgram == null || address == null) {
			clearEvidence();
			return;
		}

		setOperationState(CockpitState.OperationStatus.LOADING,
			"Loading evidence for address " + address);
		List<Evidence> evidence = evidenceService.getForAddress(currentProgram, address);
		displayEvidence(evidence);
		setOperationState(CockpitState.OperationStatus.SUCCESS, "Loaded " + evidence.size() + " items");
		statusLabel.setText(String.format("Evidence for %s: %d items", address, evidence.size()));
	}

	private void refreshEvidence() {
		if (currentEvidenceId == null) {
			clearEvidence();
			return;
		}

		setOperationState(CockpitState.OperationStatus.LOADING,
			"Loading evidence " + currentEvidenceId);
		Optional<Evidence> evidence = evidenceService.get(currentEvidenceId);
		if (evidence.isPresent()) {
			// Get the derivation chain for context
			List<Evidence> chain = evidenceService.getDerivationChain(currentEvidenceId);
			List<Evidence> allEvidence = new ArrayList<>();
			allEvidence.add(evidence.get());
			allEvidence.addAll(chain);
			displayEvidence(allEvidence);
			setOperationState(CockpitState.OperationStatus.SUCCESS,
				"Loaded " + allEvidence.size() + " items");
			statusLabel.setText("Evidence: " + currentEvidenceId);
		}
		else {
			clearEvidence();
			setOperationState(CockpitState.OperationStatus.ERROR,
				"Evidence not found: " + currentEvidenceId);
			statusLabel.setText("Evidence not found: " + currentEvidenceId);
		}
	}

	private void displayEvidence(List<Evidence> evidenceList) {
		displayEvidence(evidenceList, null);
	}

	private void displayEvidence(List<Evidence> evidenceList, SearchResultEntry hitEntry) {
		currentEvidence = new ArrayList<>(evidenceList);
		evidenceCardsPanel.removeAll();
		EvidencePacket packet = buildEvidencePacket(evidenceList, hitEntry);
		JPanel packetPanel = createEvidencePacketPanel(packet);
		evidenceCardsPanel.add(packetPanel);
		evidenceCardsPanel.add(Box.createRigidArea(new Dimension(0, 10)));

		if (hitEntry != null) {
			JPanel provenancePanel = createProvenanceOverlayPanel(packet);
			if (provenancePanel != null) {
				evidenceCardsPanel.add(provenancePanel);
				evidenceCardsPanel.add(Box.createRigidArea(new Dimension(0, 10)));
			}
		}

		// Group evidence by type
		Map<EvidenceType, List<Evidence>> byType = new LinkedHashMap<>();
		for (Evidence e : evidenceList) {
			byType.computeIfAbsent(e.getType(), k -> new ArrayList<>()).add(e);
		}

		// Create cards for each type group
		for (Map.Entry<EvidenceType, List<Evidence>> entry : byType.entrySet()) {
			JPanel typePanel = createEvidenceTypePanel(entry.getKey(), entry.getValue());
			evidenceCardsPanel.add(typePanel);
			evidenceCardsPanel.add(Box.createRigidArea(new Dimension(0, 10)));
		}

		evidenceCardsPanel.revalidate();
		evidenceCardsPanel.repaint();
	}

	private JPanel createEvidencePacketPanel(EvidencePacket packet) {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(BorderFactory.createTitledBorder(
			BorderFactory.createEtchedBorder(),
			"Evidence Packet",
			TitledBorder.LEFT,
			TitledBorder.TOP));
		panel.setAlignmentX(Component.LEFT_ALIGNMENT);

		JTextArea packetTextArea = new JTextArea(renderEvidencePacket(packet));
		packetTextArea.setEditable(false);
		packetTextArea.setLineWrap(true);
		packetTextArea.setWrapStyleWord(true);
		packetTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
		packetTextArea.setBackground(panel.getBackground());
		panel.add(packetTextArea);
		panel.add(Box.createRigidArea(new Dimension(0, 8)));
		panel.add(createTimelinePanel(packet));
		panel.add(Box.createRigidArea(new Dimension(0, 8)));
		panel.add(createLineagePanel(packet));
		return panel;
	}

	private JPanel createTimelinePanel(EvidencePacket packet) {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(BorderFactory.createTitledBorder(
			BorderFactory.createEtchedBorder(),
			"Evidence Timeline",
			TitledBorder.LEFT,
			TitledBorder.TOP));
		panel.setAlignmentX(Component.LEFT_ALIGNMENT);

		if (packet.timeline().isEmpty()) {
			panel.add(new JLabel("No timeline events"));
			return panel;
		}

		for (TimelineItem item : packet.timeline()) {
			JPanel row = new JPanel(new BorderLayout(6, 0));
			row.setAlignmentX(Component.LEFT_ALIGNMENT);
			String when = item.createdAt() != null ? TIMESTAMP_FORMATTER.format(item.createdAt()) : "unknown";
			JLabel label = new JLabel(
				"<html>" + when + " | " + item.evidenceId() + " | " + item.source() + "</html>");
			row.add(label, BorderLayout.CENTER);
			if (!item.addresses().isEmpty()) {
				Address address = item.addresses().get(0);
				JButton jumpButton = new JButton(address.toString());
				jumpButton.setMargin(new Insets(1, 4, 1, 4));
				jumpButton.setFont(jumpButton.getFont().deriveFont(10f));
				jumpButton.setToolTipText("Jump to " + address);
				jumpButton.addActionListener(e -> goToAddress(address));
				row.add(jumpButton, BorderLayout.EAST);
			}
			panel.add(row);
			panel.add(Box.createRigidArea(new Dimension(0, 3)));
		}
		return panel;
	}

	private JPanel createLineagePanel(EvidencePacket packet) {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(BorderFactory.createTitledBorder(
			BorderFactory.createEtchedBorder(),
			"Lineage Drilldown",
			TitledBorder.LEFT,
			TitledBorder.TOP));
		panel.setAlignmentX(Component.LEFT_ALIGNMENT);

		if (packet.lineage().isEmpty()) {
			panel.add(new JLabel("No lineage data"));
			return panel;
		}

		for (LineageItem item : packet.lineage()) {
			JPanel row = new JPanel(new BorderLayout(6, 0));
			row.setAlignmentX(Component.LEFT_ALIGNMENT);
			String predecessorText = item.predecessorIds().isEmpty()
					? "root"
					: String.join(", ", item.predecessorIds());
			row.add(new JLabel(item.evidenceId() + " <- " + predecessorText), BorderLayout.CENTER);
			JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 3, 0));
			for (String predecessorId : item.predecessorIds()) {
				JButton predecessorButton = new JButton(predecessorId);
				predecessorButton.setMargin(new Insets(1, 4, 1, 4));
				predecessorButton.setFont(predecessorButton.getFont().deriveFont(10f));
				predecessorButton.setToolTipText("Drill down into " + predecessorId);
				predecessorButton.addActionListener(e -> showEvidence(predecessorId));
				actionPanel.add(predecessorButton);
			}
			row.add(actionPanel, BorderLayout.EAST);
			panel.add(row);
			panel.add(Box.createRigidArea(new Dimension(0, 3)));
		}
		return panel;
	}

	private JPanel createProvenanceOverlayPanel(EvidencePacket packet) {
		if (packet.staticLinks().isEmpty() && packet.dynamicLinks().isEmpty()) {
			return null;
		}

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(BorderFactory.createTitledBorder(
			BorderFactory.createEtchedBorder(),
			"Hit Provenance Links",
			TitledBorder.LEFT,
			TitledBorder.TOP));
		panel.setAlignmentX(Component.LEFT_ALIGNMENT);
		panel.add(createProvenanceRow("Static", packet.staticLinks()));
		panel.add(Box.createRigidArea(new Dimension(0, 4)));
		panel.add(createProvenanceRow("Dynamic", packet.dynamicLinks()));
		return panel;
	}

	private JPanel createProvenanceRow(String label, List<String> links) {
		JPanel row = new JPanel(new BorderLayout(5, 0));
		JLabel titleLabel = new JLabel(label + ":");
		titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
		row.add(titleLabel, BorderLayout.WEST);
		if (links.isEmpty()) {
			JLabel noneLabel = new JLabel("none");
			noneLabel.setFont(noneLabel.getFont().deriveFont(11f));
			row.add(noneLabel, BorderLayout.CENTER);
		}
		else {
			JPanel linksPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
			for (String link : links) {
				JButton linkButton = new JButton(truncate(link, 44));
				linkButton.setMargin(new Insets(1, 4, 1, 4));
				linkButton.setFont(linkButton.getFont().deriveFont(10f));
				linkButton.setToolTipText("Jump via " + link);
				linkButton.addActionListener(e -> jumpToSource(link));
				linksPanel.add(linkButton);
			}
			row.add(linksPanel, BorderLayout.CENTER);
		}
		row.setAlignmentX(Component.LEFT_ALIGNMENT);
		return row;
	}

	private JPanel createEvidenceTypePanel(EvidenceType type, List<Evidence> evidenceList) {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(BorderFactory.createTitledBorder(
			BorderFactory.createEtchedBorder(),
			formatTypeName(type),
			TitledBorder.LEFT,
			TitledBorder.TOP));
		panel.setAlignmentX(Component.LEFT_ALIGNMENT);

		for (Evidence e : evidenceList) {
			JPanel card = createEvidenceCard(e);
			panel.add(card);
			panel.add(Box.createRigidArea(new Dimension(0, 5)));
		}

		return panel;
	}

	private JPanel createEvidenceCard(Evidence evidence) {
		JPanel card = new JPanel(new BorderLayout(5, 5));
		card.setBorder(BorderFactory.createCompoundBorder(
			BorderFactory.createLineBorder(Color.LIGHT_GRAY),
			BorderFactory.createEmptyBorder(5, 5, 5, 5)));
		card.setAlignmentX(Component.LEFT_ALIGNMENT);
		card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 100));

		// Header with source and confidence
		JPanel headerPanel = new JPanel(new BorderLayout());
		JLabel sourceLabel = new JLabel(evidence.getSource());
		sourceLabel.setFont(sourceLabel.getFont().deriveFont(Font.BOLD));

		String confidenceText = String.format("%.0f%%", evidence.getConfidence() * 100);
		JLabel confidenceLabel = new JLabel(confidenceText);
		confidenceLabel.setForeground(getConfidenceColor(evidence.getConfidence()));

		headerPanel.add(sourceLabel, BorderLayout.WEST);
		headerPanel.add(confidenceLabel, BorderLayout.EAST);

		// Address list with navigation buttons
		JPanel addressPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
		for (Address addr : evidence.getAddresses()) {
			JButton addrButton = new JButton(addr.toString());
			addrButton.setMargin(new Insets(1, 4, 1, 4));
			addrButton.setFont(addrButton.getFont().deriveFont(10f));
			addrButton.addActionListener(e -> goToAddress(addr));
			addrButton.setToolTipText("Jump to " + addr);
			addressPanel.add(addrButton);
		}

		// Payload summary
		StringBuilder payloadText = new StringBuilder();
		Map<String, Object> payload = evidence.getPayload();
		if (payload != null && !payload.isEmpty()) {
			for (Map.Entry<String, Object> entry : payload.entrySet()) {
				if (payloadText.length() > 0) {
					payloadText.append(", ");
				}
				payloadText.append(entry.getKey()).append(": ").append(entry.getValue());
			}
		}
		JLabel payloadLabel = new JLabel("<html><i>" +
			(payloadText.length() > 0 ? truncate(payloadText.toString(), 100) : "No details") +
			"</i></html>");
		payloadLabel.setFont(payloadLabel.getFont().deriveFont(11f));

		card.add(headerPanel, BorderLayout.NORTH);
		card.add(addressPanel, BorderLayout.CENTER);
		card.add(payloadLabel, BorderLayout.SOUTH);

		return card;
	}

	private void goToAddress(Address address) {
		if (currentProgram == null || address == null) {
			return;
		}

		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			goToService.goTo(new ProgramLocation(currentProgram, address));
		}
	}

	private void jumpToSource(String sourceReference) {
		Optional<Address> resolvedAddress = resolveAddressFromReference(sourceReference);
		if (resolvedAddress.isPresent()) {
			goToAddress(resolvedAddress.get());
			return;
		}
		setOperationState(CockpitState.OperationStatus.ERROR,
			"Unable to resolve source reference: " + sourceReference);
		statusLabel.setText("Unable to resolve source reference");
	}

	private Optional<Address> resolveAddressFromReference(String reference) {
		if (currentProgram == null || reference == null || reference.isBlank()) {
			return Optional.empty();
		}
		for (String token : reference.split(":")) {
			Optional<String> candidateAddress = extractHexAddressToken(token);
			if (candidateAddress.isEmpty()) {
				continue;
			}
			try {
				Address address = currentProgram.getAddressFactory().getAddress(candidateAddress.get());
				if (address != null) {
					return Optional.of(address);
				}
			}
			catch (RuntimeException ignored) {
				// Continue trying other tokens.
			}
		}
		return Optional.empty();
	}

	static Optional<String> extractHexAddressToken(String token) {
		if (token == null) {
			return Optional.empty();
		}
		String trimmed = token.trim();
		if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
			String suffix = trimmed.substring(2);
			if (suffix.matches("[0-9a-fA-F]{4,16}")) {
				return Optional.of("0x" + suffix.toLowerCase(Locale.ROOT));
			}
		}
		if (trimmed.matches("[0-9a-fA-F]{4,16}")) {
			return Optional.of("0x" + trimmed.toLowerCase(Locale.ROOT));
		}
		return Optional.empty();
	}

	private void clearEvidence() {
		currentEvidenceId = null;
		currentEvidence.clear();
		evidenceCardsPanel.removeAll();
		evidenceCardsPanel.revalidate();
		evidenceCardsPanel.repaint();
		setOperationState(CockpitState.OperationStatus.IDLE, "");
		statusLabel.setText("No evidence selected");
	}

	private void setOperationState(CockpitState.OperationStatus status, String message) {
		operationStatus = status != null ? status : CockpitState.OperationStatus.IDLE;
		operationMessage = message != null ? message : "";
	}

	private Color getConfidenceColor(double confidence) {
		if (confidence >= 0.9) {
			return new Color(0, 128, 0); // Green
		}
		else if (confidence >= 0.7) {
			return new Color(128, 128, 0); // Yellow/Olive
		}
		else if (confidence >= 0.5) {
			return new Color(200, 128, 0); // Orange
		}
		else {
			return new Color(180, 0, 0); // Red
		}
	}

	private String formatTypeName(EvidenceType type) {
		String name = type.name().replace('_', ' ');
		return name.substring(0, 1).toUpperCase() + name.substring(1).toLowerCase();
	}

	private String truncate(String text, int maxLength) {
		if (text.length() <= maxLength) {
			return text;
		}
		return text.substring(0, maxLength - 3) + "...";
	}

	EvidencePacket buildEvidencePacket(List<Evidence> evidenceList, SearchResultEntry hitEntry) {
		List<Evidence> stableEvidence = evidenceList != null
				? new ArrayList<>(evidenceList)
				: new ArrayList<>();
		stableEvidence.sort(Comparator
			.comparing(Evidence::getCreatedAt, Comparator.nullsLast(Comparator.reverseOrder()))
			.thenComparing(Evidence::getId));

		List<TimelineItem> timeline = new ArrayList<>();
		List<LineageItem> lineage = new ArrayList<>();
		for (Evidence evidence : stableEvidence) {
			timeline.add(new TimelineItem(
				evidence.getId(),
				evidence.getCreatedAt(),
				evidence.getSource(),
				List.copyOf(evidence.getAddresses())));
			lineage.add(new LineageItem(
				evidence.getId(),
				List.copyOf(evidence.getPredecessorIds())));
		}

		Set<String> staticLinks = new LinkedHashSet<>();
		Set<String> dynamicLinks = new LinkedHashSet<>();
		if (hitEntry != null) {
			for (String ref : hitEntry.getEvidenceRefs()) {
				if (ref.contains(":static:")) {
					staticLinks.add(ref);
				}
				else if (ref.contains(":dynamic:")) {
					dynamicLinks.add(ref);
				}
			}
			copyProvenanceLink(hitEntry.getProvenance(), "static_evidence_ref", staticLinks);
			copyProvenanceLink(hitEntry.getProvenance(), "static_provenance_ref", staticLinks);
			copyProvenanceLink(hitEntry.getProvenance(), "dynamic_evidence_ref", dynamicLinks);
			copyProvenanceLink(hitEntry.getProvenance(), "dynamic_provenance_ref", dynamicLinks);
		}

		return new EvidencePacket(
			List.copyOf(timeline),
			List.copyOf(lineage),
			List.copyOf(staticLinks),
			List.copyOf(dynamicLinks));
	}

	private void copyProvenanceLink(Map<String, String> provenance, String key, Set<String> links) {
		if (provenance == null || links == null) {
			return;
		}
		String value = provenance.get(key);
		if (value != null && !value.isBlank()) {
			links.add(value);
		}
	}

	static String renderEvidencePacket(EvidencePacket packet) {
		StringBuilder builder = new StringBuilder();
		builder.append("Evidence Packet\n");
		builder.append("Timeline\n");
		if (packet.timeline().isEmpty()) {
			builder.append("- none\n");
		}
		else {
			for (TimelineItem item : packet.timeline()) {
				String timestamp = item.createdAt() != null
						? TIMESTAMP_FORMATTER.format(item.createdAt())
						: "unknown";
				String addresses = item.addresses().isEmpty()
						? "-"
						: item.addresses().stream().map(Address::toString).reduce((a, b) -> a + "," + b).orElse("-");
				builder.append("- ")
					.append(timestamp)
					.append(" | ")
					.append(item.evidenceId())
					.append(" | ")
					.append(item.source())
					.append(" | ")
					.append(addresses)
					.append('\n');
			}
		}
		builder.append("Lineage\n");
		if (packet.lineage().isEmpty()) {
			builder.append("- none\n");
		}
		else {
			for (LineageItem item : packet.lineage()) {
				String predecessors = item.predecessorIds().isEmpty()
						? "root"
						: String.join(",", item.predecessorIds());
				builder.append("- ")
					.append(item.evidenceId())
					.append(" <- ")
					.append(predecessors)
					.append('\n');
			}
		}
		builder.append("Sources\n");
		builder.append("- static: ")
			.append(packet.staticLinks().isEmpty() ? "none" : String.join(",", packet.staticLinks()))
			.append('\n');
		builder.append("- dynamic: ")
			.append(packet.dynamicLinks().isEmpty() ? "none" : String.join(",", packet.dynamicLinks()));
		return builder.toString();
	}

	record TimelineItem(String evidenceId, Instant createdAt, String source, List<Address> addresses) {
	}

	record LineageItem(String evidenceId, List<String> predecessorIds) {
	}

	record EvidencePacket(List<TimelineItem> timeline, List<LineageItem> lineage,
			List<String> staticLinks, List<String> dynamicLinks) {
	}

	/**
	 * Returns the current evidence list.
	 *
	 * @return unmodifiable list of evidence
	 */
	public List<Evidence> getCurrentEvidence() {
		return Collections.unmodifiableList(currentEvidence);
	}

	public CockpitState.OperationStatus getOperationStatus() {
		return operationStatus;
	}

	public String getOperationMessage() {
		return operationMessage;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	/**
	 * Saves the provider state.
	 *
	 * @param saveState the state to save to
	 */
	public void writeConfigState(SaveState saveState) {
		saveState.putBoolean(KEY_VISIBLE, isVisible());
		if (currentEvidenceId != null) {
			saveState.putString(KEY_SELECTED_ID, currentEvidenceId);
		}
	}

	/**
	 * Restores the provider state.
	 *
	 * @param saveState the state to restore from
	 */
	public void readConfigState(SaveState saveState) {
		String savedId = saveState.getString(KEY_SELECTED_ID, null);
		if (savedId != null) {
			showEvidence(savedId);
		}
	}
}
