#!/usr/bin/python3

# Sending LLDP announcements with Python function 'os.system()'
import os

if __name__ == "__main__":
    # Run the lldpd daemon from Python
    # LLDP announcements are sent every thirty seconds
    os.system("sudo lldpd")

    # Sending a spécific LLDP announcement
    os.system("sudo lldpcli update")

