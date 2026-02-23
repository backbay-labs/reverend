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
		currentEvidence = new ArrayList<>(evidenceList);
		evidenceCardsPanel.removeAll();

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
