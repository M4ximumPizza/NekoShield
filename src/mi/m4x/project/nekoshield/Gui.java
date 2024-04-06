package mi.m4x.project.nekoguard;

import mi.m4x.project.nekoshield.Constants;
import mi.m4x.project.nekoshield.NekoShield;
import mi.m4x.project.nekoshield.Results;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Function;

public class Gui {
    public static boolean USING_GUI;
    private static JTextArea textArea;
    private static JButton searchDirPicker;
    private static Path searchDir = new File(System.getProperty("user.home")).toPath();

    private static Thread scanThread;

    public static void main(String[] args) {
        createAndDisplayGui();
    }

    private static void createAndDisplayGui() {
        boolean USING_GUI = true;
        textArea = new JTextArea(20, 40);
        JFrame frame = new JFrame();
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        // Labels and Buttons
        JLabel searchDirPickerLabel = new JLabel("Select Search Directory:");
        searchDirPickerLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        searchDirPicker = new JButton(new File(System.getProperty("user.home")).getName());
        searchDirPicker.setToolTipText("Click to choose directory");
        searchDirPicker.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            fileChooser.setFileHidingEnabled(false);
            int option = fileChooser.showOpenDialog(frame);
            if (option == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                searchDir = file.toPath();
                searchDirPicker.setText(file.getName());
            }
        });

        JCheckBox autoScrollCheckBox = new JCheckBox("Auto-scroll");
        autoScrollCheckBox.setToolTipText("Automatically scroll log output");

        JButton cancelButton = new JButton("Cancel!");
        cancelButton.setToolTipText("Cancel the current operation");
        cancelButton.setEnabled(false);
        cancelButton.addActionListener(e -> {
            if (scanThread != null) {
                NekoShield.cancelScanIfRunning();
                scanThread.interrupt();
            }
        });

        JButton runButton = new JButton("Run the scan!");
        runButton.setToolTipText("Run the scanning process");
        runButton.addActionListener(e -> {
            scanThread = new Thread(() -> {
                searchDirPicker.setEnabled(false);
                runButton.setEnabled(false);
                cancelButton.setEnabled(true);

                try {
                    Function<String, String> logOutput = out -> {
                        String processedOut = out.replace(Constants.ANSI_RED, "").replace(Constants.ANSI_GREEN, "").replace(Constants.ANSI_WHITE, "").replace(Constants.ANSI_RESET, "");
                        textArea.append(processedOut + "\n");
                        if (autoScrollCheckBox.isSelected()) {
                            textArea.setCaretPosition(textArea.getDocument().getLength());
                        }
                        return out;
                    };

                    Results run = NekoShield.run(4, searchDir, true, logOutput);
                    NekoShield.outputRunResults(run, logOutput);
                    textArea.append("Done scanning!");
                } catch (Exception ex) {
                    if (ex instanceof InterruptedException || ex instanceof RejectedExecutionException) {
                        textArea.append("Scan cancelled!" + "\n");
                    } else {
                        textArea.append("Error while running scan!" + "\n");
                    }
                }

                searchDirPicker.setEnabled(true);
                runButton.setEnabled(true);
                cancelButton.setEnabled(false);
            });
            scanThread.start();
        });

        // Create grid bag layout
        frame.getContentPane().setLayout(new GridBagLayout());
        GridBagConstraints gridBagConstraints = new GridBagConstraints();

        // Create button panel
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridBagLayout());
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        buttonPanel.add(runButton, gridBagConstraints);
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        buttonPanel.add(cancelButton, gridBagConstraints);
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        buttonPanel.add(autoScrollCheckBox, gridBagConstraints);

        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.insets = new Insets(10, 10, 10, 10);
        gridBagConstraints.anchor = GridBagConstraints.NORTHEAST;
        frame.getContentPane().add(buttonPanel, gridBagConstraints);

        // Create panel for search dir picker
        JPanel searchDirPickerPanel = new JPanel();
        searchDirPickerPanel.add(searchDirPickerLabel);
        searchDirPickerPanel.add(searchDirPicker);

        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.insets = new Insets(10, 10, 10, 10);
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        frame.getContentPane().add(searchDirPickerPanel, gridBagConstraints);

        // Create panel for log area
        JScrollPane logAreaPanel = createTextArea();

        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.weightx = 1;
        gridBagConstraints.weighty = 1;
        gridBagConstraints.insets = new Insets(10, 10, 10, 10);
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        frame.getContentPane().add(logAreaPanel, gridBagConstraints);

        // Pack and display frame
        frame.pack();
        frame.setTitle("NekoShield");
        frame.setLocationByPlatform(true);
        frame.setVisible(true);
        frame.setMinimumSize(new Dimension(600, 300));
        frame.setMaximumSize(new Dimension(600, 300));
        frame.setPreferredSize(new Dimension(600, 300));
    }

    private static JScrollPane createTextArea() {
        JScrollPane scrollPane = new JScrollPane(textArea);
        textArea.setEditable(false);

        return scrollPane;
    }
}
