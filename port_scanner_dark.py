import sys
import nmap
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLineEdit, QPushButton, QTextEdit, 
                            QLabel, QComboBox, QMessageBox, QFrame)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon

# Style sheets
DARK_STYLE = """
QMainWindow {
    background-color: #0a0a0a;
}

QWidget {
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Consolas', 'Courier New', monospace;
}

QLabel {
    color: #00ff00;
    font-weight: bold;
    border: none;
    padding: 5px;
}

QLineEdit {
    background-color: #1a1a1a;
    border: 2px solid #00ff00;
    border-radius: 5px;
    padding: 5px;
    color: #00ff00;
    font-size: 14px;
}

QLineEdit:focus {
    border: 2px solid #00ffff;
}

QPushButton {
    background-color: #1a1a1a;
    border: 2px solid #00ff00;
    border-radius: 5px;
    padding: 8px 15px;
    color: #00ff00;
    font-weight: bold;
    min-width: 100px;
}

QPushButton:hover {
    background-color: #002200;
    border: 2px solid #00ffff;
    color: #00ffff;
}

QPushButton:pressed {
    background-color: #003300;
}

QPushButton:disabled {
    background-color: #1a1a1a;
    border: 2px solid #004400;
    color: #004400;
}

QComboBox {
    background-color: #1a1a1a;
    border: 2px solid #00ff00;
    border-radius: 5px;
    padding: 5px;
    color: #00ff00;
    min-width: 150px;
}

QComboBox:hover {
    border: 2px solid #00ffff;
}

QComboBox::drop-down {
    border: none;
}

QComboBox::down-arrow {
    image: url(down_arrow.png);
    width: 12px;
    height: 12px;
}

QTextEdit {
    background-color: #0f0f0f;
    border: 2px solid #00ff00;
    border-radius: 5px;
    padding: 10px;
    color: #00ff00;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
}

QStatusBar {
    background-color: #1a1a1a;
    color: #00ff00;
    border-top: 1px solid #00ff00;
}

QFrame#ScannerFrame {
    background-color: #0f0f0f;
    border: 2px solid #00ff00;
    border-radius: 10px;
    padding: 20px;
}
"""

class ScanThread(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)  # New signal for progress updates

    def __init__(self, target, scan_type):
        super().__init__()
        self.target = target
        self.scan_type = scan_type

    def run(self):
        try:
            self.progress.emit("Initializing scan...")
            nm = nmap.PortScanner()
            
            if self.scan_type == "Quick Scan":
                self.progress.emit("Starting quick scan...")
                arguments = '-F'
            elif self.scan_type == "Full Scan":
                self.progress.emit("Starting full scan with service detection...")
                arguments = '-sS -sV'
            else:  # Common Ports
                self.progress.emit("Scanning common ports...")
                arguments = '-p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080'
            
            nm.scan(self.target, arguments=arguments)
            self.finished.emit(nm[self.target])
        except Exception as e:
            self.error.emit(str(e))

class CustomFrame(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("ScannerFrame")

class PortScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('port scanner')
        self.setGeometry(100, 100, 900, 700)
        
        # Apply dark theme
        self.setStyleSheet(DARK_STYLE)

        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Create scanner frame
        scanner_frame = CustomFrame()
        frame_layout = QVBoxLayout(scanner_frame)

        # Create title with "hacker" style
        title_label = QLabel('|| NETWORK PORT SCANNER ||')
        title_label.setFont(QFont('Consolas', 20, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        frame_layout.addWidget(title_label)

        # Add ASCII art
        ascii_art = QLabel('''
    ╔══════════════════════════════════════╗
    ║  ▄▄▄▄▄▄▄ ▄▄▄▄▄▄   ▄▄▄▄▄▄▄ ▄▄    ▄  ║
    ║  █       █   ▄  █ █       █  █  █   ║
    ║  █    ▄▄▄█  █ █ █ █       █   █▄█   ║
    ║  █   █▄▄▄█   █▄▄█▄█     ▄▄█       █ ║
    ║  █    ▄▄▄█    ▄▄  █    █  █  ▄    █ ║
    ║  █   █   █   █  █ █    █▄▄█ █ █   █ ║
    ║  █▄▄▄█   █▄▄▄█  █▄█▄▄▄▄▄▄▄█▄█  █▄█ ║
    ╚══════════════════════════════════════╝
        ''')
        ascii_art.setFont(QFont('Consolas', 8))
        ascii_art.setAlignment(Qt.AlignCenter)
        frame_layout.addWidget(ascii_art)

        # Target input area
        input_frame = QFrame()
        input_frame.setObjectName("ScannerFrame")
        input_layout = QHBoxLayout(input_frame)

        target_label = QLabel('TARGET:')
        target_label.setFont(QFont('Consolas', 12, QFont.Bold))
        input_layout.addWidget(target_label)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText('Enter IP address or hostname (e.g., 192.168.1.1)')
        self.target_input.setMinimumWidth(300)
        input_layout.addWidget(self.target_input)

        scan_type_label = QLabel('SCAN TYPE:')
        scan_type_label.setFont(QFont('Consolas', 12, QFont.Bold))
        input_layout.addWidget(scan_type_label)

        self.scan_type = QComboBox()
        self.scan_type.addItems(["Quick Scan", "Common Ports", "Full Scan"])
        input_layout.addWidget(self.scan_type)

        self.scan_button = QPushButton('[ START SCAN ]')
        self.scan_button.setFont(QFont('Consolas', 12, QFont.Bold))
        self.scan_button.clicked.connect(self.start_scan)
        input_layout.addWidget(self.scan_button)

        frame_layout.addWidget(input_frame)

        # Progress label
        self.progress_label = QLabel('STATUS: Ready')
        self.progress_label.setAlignment(Qt.AlignCenter)
        frame_layout.addWidget(self.progress_label)

        # Results area
        results_label = QLabel('[ SCAN RESULTS ]')
        results_label.setFont(QFont('Consolas', 12, QFont.Bold))
        results_label.setAlignment(Qt.AlignCenter)
        frame_layout.addWidget(results_label)

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMinimumHeight(300)
        frame_layout.addWidget(self.results_text)

        main_layout.addWidget(scanner_frame)

        # Status bar
        self.statusBar().showMessage('SYSTEM READY')

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, 'ERROR', 'Please enter a target IP or hostname')
            return

        self.scan_button.setEnabled(False)
        self.progress_label.setText('STATUS: Scanning...')
        self.statusBar().showMessage('SCAN IN PROGRESS...')
        self.results_text.clear()

        self.scan_thread = ScanThread(target, self.scan_type.currentText())
        self.scan_thread.finished.connect(self.scan_completed)
        self.scan_thread.error.connect(self.scan_error)
        self.scan_thread.progress.connect(self.update_progress)
        self.scan_thread.start()

    def update_progress(self, message):
        self.progress_label.setText(f'STATUS: {message}')

    def scan_completed(self, result):
        self.scan_button.setEnabled(True)
        self.progress_label.setText('STATUS: Scan completed')
        self.statusBar().showMessage('SCAN COMPLETED')
        
        try:
            output = """
╔════════════════════ SCAN RESULTS ════════════════════╗
"""
            # Host information
            output += f"\n║ TARGET: {self.target_input.text()}"
            if 'status' in result:
                output += f"\n║ STATE: {result['status']['state']}"
            
            output += "\n║"
            output += "\n║ OPEN PORTS:"
            output += "\n╟────────────────────────────────────────────────────"
            
            # Port information
            if 'tcp' in result:
                for port, data in result['tcp'].items():
                    output += f"\n║ PORT: {port}"
                    output += f"\n║ STATE: {data['state']}"
                    if 'name' in data:
                        output += f"\n║ SERVICE: {data['name']}"
                    if 'product' in data:
                        output += f"\n║ PRODUCT: {data['product']}"
                    if 'version' in data:
                        output += f"\n║ VERSION: {data['version']}"
                    output += "\n║ --------------------------------------------"
            
            output += "\n╚════════════════════ END REPORT ════════════════════╝"
            
            self.results_text.setText(output)
        except Exception as e:
            self.results_text.setText(f"Error formatting results: {str(e)}")

    def scan_error(self, error_message):
        self.scan_button.setEnabled(True)
        self.progress_label.setText('STATUS: Scan failed')
        self.statusBar().showMessage('SCAN FAILED')
        QMessageBox.critical(self, 'ERROR', f'Scanning error: {error_message}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # Set application-wide dark palette
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor(10, 10, 10))
    dark_palette.setColor(QPalette.WindowText, QColor(0, 255, 0))
    dark_palette.setColor(QPalette.Base, QColor(15, 15, 15))
    dark_palette.setColor(QPalette.AlternateBase, QColor(26, 26, 26))
    dark_palette.setColor(QPalette.ToolTipBase, QColor(0, 255, 0))
    dark_palette.setColor(QPalette.ToolTipText, QColor(0, 255, 0))
    dark_palette.setColor(QPalette.Text, QColor(0, 255, 0))
    dark_palette.setColor(QPalette.Button, QColor(26, 26, 26))
    dark_palette.setColor(QPalette.ButtonText, QColor(0, 255, 0))
    dark_palette.setColor(QPalette.BrightText, QColor(0, 255, 255))
    dark_palette.setColor(QPalette.Highlight, QColor(0, 85, 0))
    dark_palette.setColor(QPalette.HighlightedText, QColor(0, 255, 0))
    app.setPalette(dark_palette)
    
    window = PortScanner()
    window.show()
    sys.exit(app.exec_())