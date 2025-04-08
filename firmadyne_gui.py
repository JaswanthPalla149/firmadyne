import os
import sys
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from pathlib import Path
from tkinterdnd2 import TkinterDnD, DND_FILES

class FirmadyneGUI(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("Firmadyne Firmware Analyzer")
        self.geometry("600x400")
        
        self.firmadyne_path = os.path.dirname(os.path.abspath(__file__))
        self.output_dir = os.path.join(self.firmadyne_path, "images")
        self.sudo_password = None
        self.db_password = None
        
        self._create_widgets()
        self._check_firmadyne_structure()
    
    def _check_firmadyne_structure(self):
        """Verify required directories exist"""
        required = ["sources/extractor", "scripts", "images"]
        missing = [d for d in required if not os.path.exists(os.path.join(self.firmadyne_path, d))]
        if missing:
            messagebox.showerror("Error", f"Missing directories:\n{', '.join(missing)}")
            self.destroy()
            sys.exit(1)
    
    def _create_widgets(self):
        """Setup GUI components"""
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Drag and drop area
        self.drop_label = tk.Label(main_frame, 
                                 text="Drag Firmware Here\n(or click to browse)",
                                 relief=tk.RAISED,
                                 padx=20, pady=20,
                                 background="lightgray")
        self.drop_label.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind('<<Drop>>', self._on_drop)
        self.drop_label.bind("<Button-1>", self._browse_file)
        
        # Options
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(options_frame, text="Brand:").pack(side=tk.LEFT, padx=(0, 5))
        self.brand_var = tk.StringVar(value="Netgear")
        ttk.Entry(options_frame, textvariable=self.brand_var, width=20).pack(side=tk.LEFT)
        
        ttk.Label(options_frame, text="SQL Host:").pack(side=tk.LEFT, padx=(10, 5))
        self.sql_host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(options_frame, textvariable=self.sql_host_var, width=15).pack(side=tk.LEFT)
        
        # Analyze button
        self.analyze_button = ttk.Button(
            main_frame, 
            text="Analyze Firmware", 
            command=self._analyze_firmware,
            state=tk.DISABLED
        )
        self.analyze_button.pack(pady=(0, 10))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN).pack(fill=tk.X, side=tk.BOTTOM)
        
        self.firmware_path = None
    
    def _browse_file(self, event):
        """Handle file browsing"""
        if file_path := filedialog.askopenfilename(title="Select Firmware", filetypes=[("ZIP files", "*.zip")]):
            self._process_file(file_path)
    
    def _on_drop(self, event):
        """Handle file drop"""
        if file_path := event.data.strip('{}'):
            self._process_file(file_path)
    
    def _process_file(self, file_path):
        """Validate and set selected file"""
        if not file_path.lower().endswith('.zip'):
            messagebox.showerror("Error", "Please select a ZIP file")
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File does not exist")
            return
        
        self.firmware_path = file_path
        self.drop_label.config(text=f"Selected:\n{os.path.basename(file_path)}", background="lightgreen")
        self.analyze_button.config(state=tk.NORMAL)
    
    def _get_newest_image(self):
        """Find most recently created image file"""
        images = list(Path(self.output_dir).glob("*.tar.gz"))
        return max(images, key=os.path.getmtime) if images else None
    
    def _analyze_firmware(self):
        """Run full analysis workflow"""
        if not self.firmware_path:
            messagebox.showerror("Error", "No firmware selected")
            return
        
        try:
            # Get sudo password if needed
            if self.sudo_password is None:
                self.sudo_password = simpledialog.askstring(
                    "Sudo Password", "Enter sudo password:", show='*', parent=self
                )
                if not self.sudo_password:
                    return
            
            # Run extractor
            self.status_var.set("Extracting firmware...")
            self.update()
            
            extractor_path = os.path.join(self.firmadyne_path, "sources/extractor/extractor.py")
            cmd = [
                "sudo", "-S", "python3", extractor_path,
                "-b", self.brand_var.get(),
                "-sql", self.sql_host_var.get(),
                "-np", "-nk",
                self.firmware_path,
                "images"
            ]
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.firmadyne_path,
                text=True
            )
            stdout, stderr = process.communicate(f"{self.sudo_password}\n")
            
            if "sudo: a password is required" in stderr:
                messagebox.showerror("Error", "Incorrect sudo password")
                self.sudo_password = None
                return
            if process.returncode != 0:
                raise Exception(stderr)
            
            # Get the new image
            if not (image_path := self._get_newest_image()):
                raise Exception("No image file created")
            
            # Get database password if needed
            if self.db_password is None:
                self.db_password = simpledialog.askstring(
                    "Database Password", "Enter Firmadyne database password:", 
                    show='*', parent=self
                )
                if not self.db_password:
                    return
            
            # Analyze architecture
            self.status_var.set("Getting architecture...")
            self.update()
            
            # Create a temporary script that includes the password
            temp_script = os.path.join(self.firmadyne_path, "temp_getarch.sh")
            with open(temp_script, "w") as f:
                f.write(f"""#!/bin/bash
export PGPASSWORD='{self.db_password}'
{os.path.join(self.firmadyne_path, 'scripts/getArch.sh')} "$@"
""")
            os.chmod(temp_script, 0o755)
            
            try:
                result = subprocess.run(
                    ["bash", temp_script, str(image_path)],
                    capture_output=True, 
                    text=True, 
                    cwd=self.firmadyne_path
                )
                
                if result.returncode != 0:
                    raise Exception(result.stderr)
                
                # Show results
                messagebox.showinfo(
                    "Analysis Complete",
                    f"Image: {image_path.name}\nArchitecture: {result.stdout.strip()}"
                )
                self.status_var.set("Done")
            finally:
                # Clean up temporary script
                if os.path.exists(temp_script):
                    os.remove(temp_script)
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_var.set("Failed")
        finally:
            self.analyze_button.config(state=tk.DISABLED)
            self.drop_label.config(
                text="Drag Firmware Here\n(or click to browse)", 
                background="lightgray"
            )
            self.firmware_path = None

if __name__ == "__main__":
    app = FirmadyneGUI()
    app.mainloop()
