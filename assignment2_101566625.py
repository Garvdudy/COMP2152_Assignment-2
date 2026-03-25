"""
Author: Garv
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# Imported the required modules as said
import socket
import threading
import sqlite3
import os
import platform
import datetime


# Print Python version and OS name first bbefore start
print("Python Version:", platform.python_version())
print("Operating System:", os.name)


# Created the common_ports dictionary
# dictionary storing common port numbers and their corresponding service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


# Createing the NetworkTool parent class
class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and setter provides controlled access to private variables.
    # It ensures validation logic is applied when modifying values.
    # This prevents invalid data such as empty string.
    # It improve encapsulation & code safety.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("Networktool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, allowing it to reuse the target handling logic.
# It uses the constructor & property method without rewritng them.
# This reduces duplication and improves maintainablity.
# Inheritance helps focus only on scanning functionlity.
class PortScanner(NetworkTool):

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScaner instance destroyed")
        super().__del__()

    def scan_port(self, port):

        # Q4: What would happen without try-except here?
        # Without try-except, the program could crash when encountering connection errors.
        # For example, unreachable ports or network failures would stop execution.
        # Using try-except allows the program to contine scanning other ports.
        # It ensures robustness and reliability.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error Scanning Port {port}: {e}")

        finally:
            sock.close()

    def get_open_ports(self):
        return [res for res in self.scan_results if res[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned simultaneously, speeding up the process.
    # Scanning 1024 ports sequentially would take a long time due to delays.
    # Threads reduce total execution time significantly.
    # It improves efficiency and performamce.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


# created save_results(target, results) function
def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
        create table if not exists scans (
            id integer primary key autoincrement,
            target test,
            port integer,
            status text,
            service text,
            scan_date text
        )
        """)

        for port, status, service in results:
            cursor.execute(
                "insert into scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print("Database error:", e)


# TODO: Create load_past_scans() function (Step viii)
def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("select * from scans")
        rows = cursor.fetchall()

        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")

        conn.close()

    except:
        print("No past scans found.")


# -----------------------------------------------------------------------------------
# Mian Program
# -----------------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        target = input("Enter target IP (default 127.0.0.1): ") or "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if not (1 <= start_port <= 1024 and 1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
            exit()

        if end_port < start_port:
            print("End port must be greater than or equal to start port.")
            exit()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    scanner = PortScanner(target)

    print(f"\nScanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()

    print(f"\n--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")

    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    choice = input("Would you like to see the past scan history? (yes/no): ")
    if choice.lower() == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# One feature I would add is filtering ports by service type using a list comprehension.
# Users could choose to display only specific services like https or ssh.
# This would have improve usability n analysis of results.
# Diagram: See diagram_101566625.png in the repository root