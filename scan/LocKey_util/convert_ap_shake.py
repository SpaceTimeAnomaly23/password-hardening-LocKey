import hashlib
from statistics import mean


class AP:
    """AP class, converts a measured AP into an AP object"""

    def __init__(self, line):
        # 'ap = line' and convert ints to strings to match original code
        ap = line
        self.mac = ap[1]
        self.ssid = ap[0]
        self.flags = str(ap[2])
        self.wpa = str(ap[3])
        self.rsn = str(ap[4])
        # Disabled due instability caused by frequency hopping
        # self.freq = str(ap[5])
        self.freq = ""
        self.mode = str(ap[6])
        self.br = str(ap[7])
        self.rssi = float(str(ap[8]))

    def __eq__(self, other):
        """Overrides the default == implementation to ignore the RSSI value"""
        if isinstance(other, AP):
            return (
                    self.mac == other.mac
                    and self.ssid == other.ssid
                    and self.flags == other.flags
                    and self.wpa == other.wpa
                    and self.rsn == other.rsn
                    and self.freq == other.freq
                    and self.mode == other.mode
                    and self.br == other.br
            )

        return NotImplemented

    def __str__(self):
        """Returns the AP object a concatenated string of its values"""
        return (
                self.mac
                + ","
                + self.ssid
                + ","
                + self.flags
                + ","
                + self.wpa
                + ","
                + self.rsn
                + ","
                + self.freq
                + ","
                + self.mode
                + ","
                + self.br
                + ","
                + str(self.rssi)
        )

    def getName(self):
        return self.ssid

    def getRSSI(self):
        return self.rssi

    def setRSSI(self, rssi):
        self.rssi = float(int(mean([self.rssi, rssi])))

    def serialize(self):
        """Serializes the AP object into a SHAKE hash"""
        ap_str = ""

        number_of_bytes_to_extract = 4
        # number_of_bytes_to_extract = 3 todo: entropy argumentation (bytes_to_extract)
        # no. of bytes to extract can be set to 4

        if int(self.flags) == 0:
            x = 2
        else:
            x = int(self.flags)

        hashes = []
        m = hashlib.shake_128()
        m.update(self.ssid.encode())
        m.update(self.mac.encode())
        m.update(self.flags.encode())
        m.update(self.wpa.encode())
        m.update(self.rsn.encode())
        m.update(self.freq.encode())
        m.update(self.mode.encode())
        m.update(self.br.encode())
        ap_str = bin(int(m.hexdigest(number_of_bytes_to_extract), 16))[2:]
        return int(ap_str, 2), ap_str, self.rssi


def convert_scan_data_to_shake(scan_data_in):
    """
    Converts #todo: continue
    :param scan_data_in:
    :return:
    """
    aps_shakes = {}
    for aps in scan_data_in:
        shake = convert_single_ap_to_shake(aps)
        aps_shakes.update(shake)
    shake_list_out = aps_shakes.keys()
    return shake_list_out


def convert_single_ap_to_shake(aps: list):
    """
    Creates and returns a shake-representation list of a single Wi-Fi scan. Removes duplicates
    :param aps: List of access point data
    :return: List of access points in shake-representation
    """
    full_scan = []
    shake_ap_data = []
    for access_point in aps:
        try:
            a = AP(access_point)
        except Exception as e:
            print(e)
            print("*****")
            input(access_point)

        # Remove duplicates
        if a not in full_scan:
            x = a.serialize()
            x = (x[0], x[2])
            full_scan.append(x)

    tmp = set()
    out = []

    for a, b in full_scan:
        if a not in tmp:
            tmp.add(a)
            out.append([a, b])
    for o in out:
        shake_ap_data.append(o)
    return shake_ap_data
