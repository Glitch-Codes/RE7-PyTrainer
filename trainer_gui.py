import sys
import pymem
import utility
from AOBCheats.god_mode import GodMode
from AOBCheats.no_spread import NoSpread
from PointerCheats.no_reload import NoReload
from PointerCheats.infinite_ammo import InfiniteAmmo
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QCheckBox, QLabel, QGroupBox, QPushButton)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont
import time


class TrainerThread(QThread):
    status_update = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.running = True
        self.unlimited_pistol_ammo = False
        self.no_reload_enabled = False
        self.god_mode_enabled = False
        self.one_hit_kill = False
        self.no_spread_enabled = False
        self.infinite_ammo_enabled = False
        
        self.process = None
        self.proc_handle = None
        self.base_address = None
        self.pistol_ammo_addr = None
        self.health_addr = None
        self.ammo_op_code_addr = None
        self.god_mode = None
        self.no_spread = None
        self.no_reload = None
        self.infinite_ammo = None
        
    def run(self):
        try:
            # Initialize process
            self.process = pymem.Pymem("re7.exe")
            gameModule = pymem.process.module_from_name(self.process.process_handle, "re7.exe").lpBaseOfDll
            self.proc_handle = self.process.process_handle
            self.base_address = self.process.base_address
            
            self.status_update.emit(f"Connected to RE7 - Base: {hex(self.base_address)}")
            
            if gameModule != self.base_address:
                self.error_signal.emit("Discrepancy between Game Module and Base Address")
                return
            
            self.pistol_ammo_addr = utility.getPointerAddr(self.process, self.base_address + 0x08FE7A88, [0x60, 0xA0, 0x210, 0x50, 0x9A8, 0x2E4])
            
            # Initialize god mode
            self.god_mode = GodMode(self.process, self.proc_handle, self.base_address)

            # Initialize no spread
            self.no_spread = NoSpread(self.process, self.proc_handle, self.base_address)
            
            # Initialize no reload
            self.no_reload = NoReload(self.process, self.proc_handle, self.base_address)

            # Initialize inifinite ammo
            self.infinite_ammo = InfiniteAmmo(self.process, self.proc_handle, self.base_address)

            self.status_update.emit("Addresses resolved. Trainer active.")
            
            # Main loop
            while self.running:
                try:
                    # Handle unlimited pistol ammo
                    if self.unlimited_pistol_ammo:
                        pistol_ammo = self.process.read_int(self.pistol_ammo_addr)
                        if pistol_ammo < 99:
                            self.process.write_int(self.pistol_ammo_addr, 99)
                    
                    # Handle no reload
                    if self.no_reload_enabled and self.no_reload and not self.no_reload.enabled:
                        if self.no_reload.enable():
                            self.status_update.emit("No Reload Activated!")
                        else:
                            self.error_signal.emit("Failed to enable No Reload")
                            self.no_reload_enabled = False
                    elif not self.no_reload_enabled and self.no_reload and self.no_reload.enabled:
                        self.no_reload.disable()
                        self.status_update.emit("No Reload Deactivated")

                    # Handle infinite ammo
                    if self.infinite_ammo_enabled and self.infinite_ammo and not self.infinite_ammo.enabled:
                        if self.infinite_ammo.enable():
                            self.status_update.emit("Infinite Ammo Activated!")
                        else:
                            self.error_signal.emit("Failed to enable Infinite Ammo")
                            self.infinite_ammo_enabled = False
                    elif not self.infinite_ammo_enabled and self.infinite_ammo and self.infinite_ammo.enabled:
                        self.infinite_ammo.disable()
                        self.status_update.emit("Infinite Ammo Deactivated")

                    # Handle no spread
                    if self.no_spread_enabled and self.no_spread and not self.no_spread.enabled:
                        if self.no_spread.enable():
                            self.status_update.emit("No Spread Activated!")
                        else:
                            self.error_signal.emit("Failed to enable No Spread")
                            self.no_spread_enabled = False
                    elif not self.no_spread_enabled and self.no_spread and self.no_spread.enabled:
                        self.no_spread.disable()
                        self.status_update.emit("No Spread Deactivated")
                    
                    # Handle god mode
                    if self.god_mode_enabled and self.god_mode and not self.god_mode.enabled:
                        if self.god_mode.enable():
                            self.status_update.emit("God Mode Activated!")
                        else:
                            self.error_signal.emit("Failed to enable God Mode")
                            self.god_mode_enabled = False
                    elif not self.god_mode_enabled and self.god_mode and self.god_mode.enabled:
                        self.god_mode.disable()
                        self.status_update.emit("God Mode Deactivated")
                    
                    # Handle one hit kill
                    if self.god_mode and self.god_mode.enabled:
                        self.god_mode.set_one_hit_kill(self.one_hit_kill)
                    
                    time.sleep(0.1)  # Reduced CPU usage
                    
                except Exception as e:
                    self.error_signal.emit(f"Runtime error: {str(e)}")
                    print("Runtime error in trainer loop:", e)
                    time.sleep(1)
                    
        except Exception as e:
            self.error_signal.emit(f"Initialization error: {str(e)}")
    
    def stop(self):
        self.running = False
        # Disable god mode if enabled
        if self.god_mode and self.god_mode.enabled:
            self.god_mode.disable()
        # Disable no spread if enabled
        if self.no_spread and self.no_spread.enabled:
            self.no_spread.disable()
        # Disable no reload if enabled
        if self.no_reload and self.no_reload.enabled:
            self.no_reload.disable()
        # Disable infinite ammo if enabled
        if self.infinite_ammo and self.infinite_ammo.enabled:
            self.infinite_ammo.disable()
        self.wait()


class TrainerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.trainer_thread = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("RE7 Trainer")
        self.setGeometry(100, 100, 400, 500)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Resident Evil 7 - Trainer")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #ff6b6b; padding: 10px;")
        layout.addWidget(title)
        
        # Status label
        self.status_label = QLabel("Status: Not Connected")
        self.status_label.setStyleSheet("background-color: #1e1e1e; padding: 10px; border-radius: 5px;")
        layout.addWidget(self.status_label)
        
        # Cheats group
        cheats_group = QGroupBox("Cheats")
        cheats_group.setStyleSheet("""
            QGroupBox {
                border: 2px solid #444444;
                border-radius: 5px;
                margin-top: 10px;
                padding: 15px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        cheats_layout = QVBoxLayout()
        
        # Unlimited Pistol Ammo checkbox
        self.unlimited_pistol_ammo_checkbox = QCheckBox("Unlimited Pistol Ammo (Set to 99)")
        self.unlimited_pistol_ammo_checkbox.setStyleSheet("padding: 5px; font-size: 12px;")
        self.unlimited_pistol_ammo_checkbox.stateChanged.connect(self.toggle_unlimited_pistol_ammo)
        cheats_layout.addWidget(self.unlimited_pistol_ammo_checkbox)
        
        # No Reload checkbox
        self.no_reload_checkbox = QCheckBox("No Reload (Opcode Patch)")
        self.no_reload_checkbox.setStyleSheet("padding: 5px; font-size: 12px;")
        self.no_reload_checkbox.stateChanged.connect(self.toggle_no_reload)
        cheats_layout.addWidget(self.no_reload_checkbox)

        # Infinite Ammo checkbox
        self.infinite_ammo_checkbox = QCheckBox("Infinite Ammo (Opcode Patch)")
        self.infinite_ammo_checkbox.setStyleSheet("padding: 5px; font-size: 12px;")
        self.infinite_ammo_checkbox.stateChanged.connect(self.toggle_infinite_ammo)
        cheats_layout.addWidget(self.infinite_ammo_checkbox)
        
        # No Spread checkbox
        self.no_spread_checkbox = QCheckBox("No Spread (Opcode Patch)")
        self.no_spread_checkbox.setStyleSheet("padding: 5px; font-size: 12px;")
        self.no_spread_checkbox.stateChanged.connect(self.toggle_no_spread)
        cheats_layout.addWidget(self.no_spread_checkbox)
        
        # God Mode checkbox
        self.god_mode_checkbox = QCheckBox("God Mode (Invincibility)")
        self.god_mode_checkbox.setStyleSheet("padding: 5px; font-size: 12px;")
        self.god_mode_checkbox.setEnabled(False)
        #self.god_mode_checkbox.stateChanged.connect(self.toggle_god_mode)
        #cheats_layout.addWidget(self.god_mode_checkbox)
        
        # One Hit Kill checkbox
        self.one_hit_kill_checkbox = QCheckBox("One Hit Kill Enemies (Requires God Mode)")
        self.one_hit_kill_checkbox.setStyleSheet("padding: 5px; font-size: 12px;")
        self.one_hit_kill_checkbox.setEnabled(False)
        #self.one_hit_kill_checkbox.stateChanged.connect(self.toggle_one_hit_kill)
        #cheats_layout.addWidget(self.one_hit_kill_checkbox)
        
        cheats_group.setLayout(cheats_layout)
        layout.addWidget(cheats_group)
        
        # Control buttons
        self.start_button = QPushButton("Start Trainer")
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #666666;
            }
        """)
        self.start_button.clicked.connect(self.start_trainer)
        layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop Trainer")
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #666666;
            }
        """)
        self.stop_button.clicked.connect(self.stop_trainer)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)
        
        layout.addStretch()
        
        # Credits
        credits = QLabel("Made for RE7 by Glitch • Github.com/Glitch-Codes")
        credits.setAlignment(Qt.AlignCenter)
        credits.setStyleSheet("color: #888888; font-size: 10px; padding: 10px;")
        layout.addWidget(credits)
        
        central_widget.setLayout(layout)
        
        # Disable checkboxes initially
        self.set_checkboxes_enabled(False)
    
    def start_trainer(self):
        self.trainer_thread = TrainerThread()
        self.trainer_thread.status_update.connect(self.update_status)
        self.trainer_thread.error_signal.connect(self.show_error)
        self.trainer_thread.start()
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.set_checkboxes_enabled(True)
    
    def stop_trainer(self):
        if self.trainer_thread:
            self.update_status("Stopping trainer...")
            self.trainer_thread.stop()
            self.trainer_thread = None
        
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.set_checkboxes_enabled(False)
        self.update_status("Status: Disconnected")
        
        # Reset checkboxes
        self.unlimited_pistol_ammo_checkbox.setChecked(False)
        self.no_reload_checkbox.setChecked(False)
        self.infinite_ammo_checkbox.setChecked(False)
        self.no_spread_checkbox.setChecked(False)
        self.god_mode_checkbox.setChecked(False)
        self.one_hit_kill_checkbox.setChecked(False)
    
    def toggle_unlimited_pistol_ammo(self, state):
        if self.trainer_thread:
            self.trainer_thread.unlimited_pistol_ammo = (state == Qt.Checked)
    
    def toggle_no_reload(self, state):
        if self.trainer_thread:
            self.trainer_thread.no_reload_enabled = (state == Qt.Checked)

    def toggle_infinite_ammo(self, state):
        if self.trainer_thread:
            self.trainer_thread.infinite_ammo_enabled = (state == Qt.Checked)

    def toggle_no_spread(self, state):
        if self.trainer_thread:
            self.trainer_thread.no_spread_enabled = (state == Qt.Checked)
    
    def toggle_god_mode(self, state):
        if self.trainer_thread:
            self.trainer_thread.god_mode_enabled = (state == Qt.Checked)
    
    def toggle_one_hit_kill(self, state):
        if self.trainer_thread:
            self.trainer_thread.one_hit_kill = (state == Qt.Checked)
    
    def set_checkboxes_enabled(self, enabled):
        self.unlimited_pistol_ammo_checkbox.setEnabled(enabled)
        self.no_reload_checkbox.setEnabled(enabled)
        self.infinite_ammo_checkbox.setEnabled(enabled)
        self.no_spread_checkbox.setEnabled(enabled)
        self.god_mode_checkbox.setEnabled(enabled)
        self.one_hit_kill_checkbox.setEnabled(enabled)
    
    def update_status(self, message):
        self.status_label.setText(f"Status: {message}")
    
    def show_error(self, message):
        self.status_label.setText(f"Error: {message}")
        self.status_label.setStyleSheet("background-color: #8b0000; padding: 10px; border-radius: 5px;")
    
    def closeEvent(self, event):
        if self.trainer_thread:
            self.stop_trainer()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = TrainerGUI()
    gui.show()
    sys.exit(app.exec_())
