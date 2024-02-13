import os
import subprocess
import time

import NetworkManager
import dbus.mainloop.glib

from util.logger import Logger


def single_scan():
    """
    Single Wi-Fi scan. Returns a list of access-point data (SSID, MAC, etc...)
    """
    Logger.info("Scanning WiFi...")

    results = []
    ap_list = []
    try:
        force_wifi_rescan()
        wifi_network_list = get_wifi()
        if len(wifi_network_list) < 2:
            warning_info = 'Inspect /' + os.path.basename(os.getcwd()) + '/scanner.py def single_Scan()'
            Logger.warning("Possible hardware scan bug. Only 1 AP detected. %s", warning_info)
            force_wifi_rescan()
        if len(wifi_network_list) > 0:
            ap_list.extend(wifi_network_list)
        else:
            Logger.warning("SCANNER: no aps detected")
            Logger.warning("Is your WLAN turned on?")
    except Exception as e:
        Logger.warning(e)
        Logger.warning("Please report this exception")
    results.append(ap_list)
    Logger.debug("SINGLE scan APs: %d", len(results[0]))
    return results


def force_wifi_rescan():
    """Using NetworkManager Command-Line Interface to rescan and update the system's list of Wi-Fi access points"""
    start = time.time()
    Logger.debug("NMCLI force rescan...")
    command = ['nmcli', 'device', 'wifi', 'list', '--rescan', 'yes']
    subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = time.time()
    delta_t = end - start
    Logger.debug("scan time: %f", delta_t)


def get_wifi() -> list[list]:
    """
    Retrieves a list of available Wi-Fi networks using NetworkManager.

    This function initializes the D-Bus main loop, queries NetworkManager for a list of available Wi-Fi access points,
    and extracts relevant information about each access point, including SSID, hardware address, security flags, frequency,
    mode, and signal strength.

    Returns:
        list[list]: A list of Wi-Fi networks, where each network is represented as a list containing the following information:
            SSID, Hardware Address, Flags, WpaFlags, RsnFlags, Frequency, Mode, MaxBitrate and Signal Strength.
    """
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    wifi_network_list = []

    for ap in NetworkManager.AccessPoint.all():
        try:
            wifi_network_list.append(
                [ap.Ssid, ap.HwAddress, ap.Flags, ap.WpaFlags, ap.RsnFlags, ap.Frequency, ap.Mode, ap.MaxBitrate,
                 ap.Strength])

        except NetworkManager.ObjectVanished:
            pass
    return wifi_network_list
