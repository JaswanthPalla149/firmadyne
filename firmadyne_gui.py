import os
import sys
import subprocess
import pexpect
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from pathlib import Path
import threading

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
except ImportError:
    messagebox.showerror("Error", "Please install tkinterdnd2: pip install tkinterdnd2")
    sys.exit(1)

class FirmadyneGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Firmadyne Firmware Analyzer")
        self.root.geometry("600x400")
       
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
            self.root.destroy()
            sys.exit(1)
   
    def _create_widgets(self):
        """Setup GUI components"""
        main_frame = ttk.Frame(self.root, padding="10")
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
   
    def _browse_file(self, event=None):
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
   
    def _get_image_number(self, image_path):
        """Extract just the numeric ID from image filename"""
        return os.path.basename(image_path).split('.')[0]
   
    def _analyze_firmware(self):
        """Run full analysis workflow"""
        if not self.firmware_path:
            messagebox.showerror("Error", "No firmware selected")
            return
       
        try:
            # Get sudo password if needed
            if self.sudo_password is None:
                self.sudo_password = simpledialog.askstring(
                    "Sudo Password", "Enter sudo password:", show='*', parent=self.root
                )
                if not self.sudo_password:
                    return
           
            # Run extractor
            self.status_var.set("Extracting firmware...")
            self.root.update()
           
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
            print("Running command:", ' '.join(cmd))
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
                    show='*', parent=self.root
                )
                if not self.db_password:
                    return
            env = os.environ.copy()
            env["PGPASSWORD"] = self.db_password
           
            # Analyze architecture
            self.status_var.set("Getting architecture...")
            self.root.update()
           
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
               
                # After architecture detection succeeds:
                image_name = self._get_image_number(image_path)
               
                # Step 1: Load filesystem into database
                self.status_var.set("Loading filesystem into DB...")
                self.root.update()
               
                tar2db_cmd = [
                    "python3",
                    os.path.join(self.firmadyne_path, "scripts/tar2db.py"),
                    "-i", image_name,
                    "-f", str(image_path)
                ]
                print("Running command:", ' '.join(tar2db_cmd))
                tar2db_result = subprocess.run(
                    tar2db_cmd,
                    capture_output=True,
                    text=True,
                    cwd=self.firmadyne_path
                )
               
                # Check if error is about duplicate entries
                if tar2db_result.returncode != 0:
                    if "duplicate key value violates unique constraint" in tar2db_result.stderr:
                        duplicate_info = ""
                        if "DETAIL:" in tar2db_result.stderr:
                            duplicate_info = "\n" + tar2db_result.stderr.split("DETAIL:")[1].strip()
                       
                        response = messagebox.askyesno(
                            "Duplicate Firmware Detected",
                            f"This firmware appears to already exist in the database.{duplicate_info}\n\n"
                            "Do you want to continue with disk creation and emulation using the existing database entries?",
                            parent=self.root
                        )
                       
                        if not response:
                            raise Exception("Operation cancelled by user")
                    else:
                        raise Exception(f"Failed to load filesystem to DB:\n{tar2db_result.stderr}")
               
                # Step 2: Create QEMU disk image
                self.status_var.set("Creating QEMU image...")
                self.root.update()
                image_name = self._get_image_number(image_path)
                command = f'./scripts/makeImage.sh {image_name}'
                full_command = f'echo {self.sudo_password} | sudo -SE bash -c "{command}"'
                p = subprocess.run(full_command, shell=True, env=env, capture_output=True, text=True)

                print("Running command:", command)  
                print("Sudo Pass:", self.sudo_password)
                print("Firmadyne DB Pass:", self.db_password)
                print("STDOUT:", p.stdout)
                print("STDERR:", p.stderr)
                print("Return code:", p.returncode)
               
                # Step 3: Infer network configuration
                self.status_var.set("Inferring network config...")
                self.root.update()
                image_name = self._get_image_number(image_path)
                command2 = f'./scripts/inferNetwork.sh {image_name}'
                print("Running command:", command2)
                full_command2 = f'echo {self.sudo_password} | sudo -SE bash -c "{command2}"'
                p = subprocess.run(full_command2, shell=True, env=env, capture_output=True, text=True)

                print("STDOUT:", p.stdout)
                print("STDERR:", p.stderr)
                print("Return code:", p.returncode)
               
                # Step 4: Emulate firmware and run analyses
                self.status_var.set("Starting emulation and analyses...")
                self.root.update()

                run_script_path = os.path.join(self.firmadyne_path, f"scratch/{image_name}/run.sh")
                if not os.path.exists(run_script_path):
                    raise Exception("Run script not found")

                # Create a new window for showing analysis results
                analysis_window = tk.Toplevel(self.root)
                analysis_window.title("Analysis Results")
                analysis_window.geometry("800x600")

                # Create text widgets for each analysis output
                notebook = ttk.Notebook(analysis_window)
                notebook.pack(fill='both', expand=True)
                # ================= TERMINAL TAB =================
                terminal_tab = ttk.Frame(notebook)
                notebook.add(terminal_tab, text="Terminal")

                # Terminal output frame
                terminal_frame = ttk.Frame(terminal_tab)
                terminal_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

                # Terminal output display
                terminal_text = tk.Text(
                terminal_frame,
                wrap=tk.WORD,
                bg='black',
                fg='white',
                insertbackground='white',
                font=('Courier', 10)
                )
                terminal_scroll = ttk.Scrollbar(terminal_frame, command=terminal_text.yview)
                terminal_text.config(yscrollcommand=terminal_scroll.set)
                terminal_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                terminal_scroll.pack(side=tk.RIGHT, fill=tk.Y)

                # Terminal control buttons
                term_button_frame = ttk.Frame(terminal_tab)
                term_button_frame.pack(fill=tk.X, padx=10, pady=5)

                stop_button = ttk.Button(
                term_button_frame,
                text="Stop Emulation",
                command=lambda: self._stop_emulation(analysis_window)
                )
                stop_button.pack(side=tk.LEFT, padx=5)

                clear_button = ttk.Button(
                    term_button_frame,
                    text="Clear Terminal",
                    command=lambda: terminal_text.delete(1.0, tk.END)
                )
                clear_button.pack(side=tk.LEFT, padx=5)
                

                # Frames for each analysis tab
                emulation_tab = tk.Frame(notebook)
                snmp_tab = tk.Frame(notebook)
                web_tab = tk.Frame(notebook)
                nmap_tab = tk.Frame(notebook)

                notebook.add(emulation_tab, text="Emulation")
                notebook.add(snmp_tab, text="SNMP")
                notebook.add(web_tab, text="Web Access")
                notebook.add(nmap_tab, text="NMAP")

                # Text widgets with scrollbars
                def create_output_widget(parent):
                    frame = tk.Frame(parent)
                    scroll = tk.Scrollbar(frame)
                    text = tk.Text(frame, wrap=tk.WORD, yscrollcommand=scroll.set)
                    scroll.config(command=text.yview)
                    scroll.pack(side=tk.RIGHT, fill=tk.Y)
                    text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                    frame.pack(fill=tk.BOTH, expand=True)
                    return text

                emulation_output = create_output_widget(emulation_tab)
                snmp_output = create_output_widget(snmp_tab)
                web_output = create_output_widget(web_tab)
                nmap_output = create_output_widget(nmap_tab)

                self.emulation_process = None

                # Function to run commands and update UI
                def run_analyses():
                    ip_address = "192.168.0.100"  # You might want to make this configurable
                    log_file = os.path.join(self.firmadyne_path, f"scratch/{image_name}/analyses.log")
                   
                    # Run emulation
                    emulation_process = subprocess.Popen(
                        [run_script_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True
                    )
                    self.emulation_process = emulation_process 
                    # Run SNMP analysis
                    snmp_process = subprocess.Popen(
                        [os.path.join(self.firmadyne_path, "analyses/snmpwalk.sh"), ip_address],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True
                    )
                   
                    # Run web access analysis
                    web_process = subprocess.Popen(
                        ["sudo", "-S", "python3", os.path.join(self.firmadyne_path, "analyses/webAccess.py"), "1", ip_address, log_file],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True
                    )
                   
                    # Run NMAP scan
                    nmap_process = subprocess.Popen(
                        ["sudo", "nmap", "-O", "-sV", ip_address],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True
                    )
                   
                    # Function to read output and update UI
                    def update_output(process, output_widget):
                        line = process.stdout.readline()
                        while True:
                            if not line and process.poll() is not None:
                                    break
                            if line:
                                break
                            output_widget.insert(tk.END, line)
                            output_widget.see(tk.END)
                            output_widget.update_idletasks()
                        process.stdout.close()
                       
                   # Helper method to monitor process output
                    def _monitor_process_output(self, process, output_widget):
                            def update_output():
                                while True:
                                    line = process.stdout.readline()
                                    if not line and process.poll() is not None:
                                        break
                                    if line:
                                        output_widget.insert(tk.END, line)
                                        output_widget.see(tk.END)
                                        output_widget.update_idletasks()
                                process.stdout.close()
                    # Start threads to monitor each process output
                    threading.Thread(target=update_output, args=(emulation_process, emulation_output), daemon=True).start()
                    threading.Thread(target=update_output, args=(snmp_process, snmp_output), daemon=True).start()
                    threading.Thread(target=update_output, args=(web_process, web_output), daemon=True).start()
                    threading.Thread(target=update_output, args=(nmap_process, nmap_output), daemon=True).start()
                    def monitor_process_output(process, output_widget):
                        try:
                            while True:
                                line = process.stdout.readline()
                                if not line and process.poll() is not None:  # Process ended
                                    break
                                if line:
                                    output_widget.insert(tk.END, line)
                                    output_widget.see(tk.END)
                                    output_widget.update_idletasks()
                        except ValueError:  # Catch "I/O on closed file"
                            output_widget.insert(tk.END, "\n[Process terminated unexpectedly]\n")
                    monitor_process_output(emulation_process, emulation_output)
                    monitor_process_output(snmp_process, snmp_output)
                    monitor_process_output(web_process, web_output)
                    monitor_process_output(nmap_process, nmap_output)

                # Start the analyses in a separate thread to keep UI responsive
                threading.Thread(target=run_analyses, daemon=True).start()
                # Terminal input entry field
                terminal_input = ttk.Entry(term_button_frame, width=80)
                terminal_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
                # Terminal input handling
                def send_terminal_input(event=None):
                        user_input = terminal_input.get()
                        if self.emulation_process and self.emulation_process.stdin:
                            try:
                                self.emulation_process.stdin.write(user_input + "\n")
                                self.emulation_process.stdin.flush()
                            except Exception as e:
                                messagebox.showerror("Terminal Error", f"Failed to send input: {e}")
                        terminal_input.delete(0, tk.END)
                terminal_input.bind("<Return>", send_terminal_input) 
                # Window close handler
                def on_analysis_window_close():
                    try:
                         if messagebox.askokcancel("Quit", "Stop emulation and close this window?"):
                                if self.emulation_process and self.emulation_process.poll() is None:
                                    self.emulation_process.terminate()
                                    time.sleep(1)
                                    if self.emulation_process.poll() is None:
                                        self.emulation_process.kill()
                                #self._stop_emulation(analysis_window)
                                if analysis_window.winfo_exists():
                                    analysis_window.destroy()
                    except Exception as e:
                                    messagebox.showerror("Error", f"Error during shutdown: {str(e)}")

               
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
    root = TkinterDnD.Tk()
    app = FirmadyneGUI(root)
    root.mainloop()
