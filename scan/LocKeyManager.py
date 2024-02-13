import hashlib
import os
import time
from collections import Counter

from scan.LocKey_util.convert_ap_shake import convert_scan_data_to_shake
from scan.LocKey_util.scanner import single_scan
from util.logger import *
from util.util import flatten


class LocKeyManager:
    """
    A class to manage LocKey's variables and functions
    """

    def __init__(self, min_beacon_frame_entropy: float, wanted_key_entropy: int, number_of_calibration_scans: int):
        self.__MIN_BEACON_FRAME_ENTROPY = min_beacon_frame_entropy
        self.__WANTED_KEY_ENTROPY = wanted_key_entropy
        self.__AP_DETECTION_THRESHOLD = 0.1
        self.number_of_calibration_scans = number_of_calibration_scans

        self.__APR_LENGTH = 32
        self.PRIME_MODULUS = (2 ** 129) - 25
        self.OUTPUT_RANGE = 2 ** 128
        self.max_corrections = 0
        self.scan_counter = 1
        self.valid_ap_shakes = {}

    def calibration_scan(self, scan_time: int = None):
        """
        This function performs scans using the calibration time set in the LocKeyManager class. A location is
        scanned using the `single_scan` function and converted into shake-format.
        :return: List of lists containing APs from each scan in shake-format.
        """
        if scan_time is None:
            scan_time = self.number_of_calibration_scans

        scans_in_shake_format = []
        for _ in range(0, scan_time):
            raw_ap_data = single_scan()
            single_scan_shakes = list(convert_scan_data_to_shake(raw_ap_data))
            scans_in_shake_format.append(single_scan_shakes)
            Logger.info("Scan %d complete", self.scan_counter)
            self.scan_counter += 1
            # print(scans_in_shake_format)

        return scans_in_shake_format

    def check_entropy(self, wifi_fingerprint, number_of_scans: int = None) -> bool:
        """
        If the Wi-Fi fingerprint contains enough entropy, valid APs are filtered and stored in the LocKeyManager's self.valid_ap_shakes.
        :param number_of_scans: The number of scans used to create the Wi-Fi fingerprint. Important for entropy calculation
        :param wifi_fingerprint: APs data in shake format
        :return: True or False depending on if the input data contains enough entropy
        """
        if number_of_scans is None:
            number_of_scans = self.number_of_calibration_scans
        # loop through the content to check if locations provide sufficient entropy
        cutoff_counter = 0
        access_points = flatten(wifi_fingerprint)
        ap_counter = Counter(access_points)
        valid_aps = {}
        for x in ap_counter:
            p = ap_counter[x] / number_of_scans
            if p >= self.__AP_DETECTION_THRESHOLD:
                valid_aps.update({x: p})
            else:
                cutoff_counter += 1
        Logger.debug("Cutoffs: %s", str(cutoff_counter))
        self.valid_ap_shakes = list(valid_aps.keys())
        entropy = len(list(set(self.valid_ap_shakes))) * self.__MIN_BEACON_FRAME_ENTROPY
        Logger.debug("entropy: %f", entropy)

        if entropy < self.__WANTED_KEY_ENTROPY:
            Logger.info("Entropy is too low")
            return False
        else:
            self.max_corrections = int((entropy - self.__WANTED_KEY_ENTROPY) / self.__APR_LENGTH)
            Logger.debug("Enough entropy in APs")
            Logger.debug("APs: %s", len(self.valid_ap_shakes))
            Logger.debug("possible corrections : %d", self.max_corrections)
            return True

    def create_secure_sketch(self):
        """
        Creates the secure sketch and save it to file as 'template.ss'
        """
        root_path = os.getcwd() + '/sets'

        try:
            self.create_template()
            # create secure sketch. filename: template.ss
            os.system("./sketch " + root_path + '/template.set >/dev/null 2>&1')
        finally:
            # remove the file template.set
            if os.path.exists(root_path + '/template.set'):
                os.remove(root_path + '/template.set')

    def delete_secure_sketch(self):
        """
        Deletes the file 'template.ss'
        """
        secure_sketch_path = os.getcwd() + '/template.ss'
        if os.path.exists(secure_sketch_path):
            os.remove(secure_sketch_path)

    def create_template(self, filename: str = None):
        """
        Creates the file 'template.set' which is needed to call PinSketch to create a secure sketch.
        The file contains number of corrections, m and the list of APs in shake format.

        DELETE 'template.set' after calling PinSketch!
        """
        if filename is None:
            filename = '/template.set'

        root_path = os.getcwd() + '/sets'
        # create the file template.set
        with open(root_path + filename, 'w') as outfile:
            outfile.write('t=%s\n' % self.max_corrections)
            outfile.write('m=' + str(self.__APR_LENGTH) + '\n\n[\n')
            for shake in self.valid_ap_shakes:
                outfile.write(str(shake) + '\n')
            outfile.write('\n]')

    def generate_key_from_wifi_fingerprint(self, WiFi_finger_print, helper_data: tuple[int, int]) -> bytes:
        """
        Generates a cryptographic key from a Wi-Fi fingerprint.

        :param WiFi_finger_print: A set of detected and filtered access points
        :param helper_data: LocKey helper data coefficient a and b
        :return: A cryptographic key generated from the Wi-Fi fingerprint
        """
        WiFi_finger_print = [str(x) for x in WiFi_finger_print]
        WiFi_finger_print.sort()
        shake = hashlib.shake_128()
        for access_point in WiFi_finger_print:
            shake.update(access_point.encode("utf-8"))
        r = int(shake.hexdigest(16), 16)
        key = ((helper_data[0] * r + helper_data[1]) % self.PRIME_MODULUS) % self.OUTPUT_RANGE
        return key

    def reconstruct_key(self, helper_data):
        """
        Reconstructs a cryptographic key from Wi-Fi fingerprint data. Since the secure-sketch is needed as a file,
        it has to be extracted and written to file before calling this method.

        :param helper_data:  LocKey helper data coefficients
        :return: A cryptographic key generated from the Wi-Fi fingerprint
        """

        # Call differ to reconstruct original WiFi_finger_print
        root_path = os.getcwd() + '/sets'
        restored_sketch_path = root_path + '/restored.ss'
        current_set_path = root_path + '/current.set'
        # execute PinSketch with secure-sketch and current set. e.g.: ./differ template.ss current.set
        os.system(
            "./differ "
            + restored_sketch_path
            + " "
            + current_set_path
            + "> /dev/null 2>&1"
        )

        time.sleep(0.1)
        with open(root_path + '/current.set') as infile:
            current_set = [line[:-1] for line in infile.readlines()][4:-2]

        with open(os.getcwd() + "/differ.set") as infile2:
            APs_to_correct = [line[:-1] for line in infile2.readlines()]

        to_add = [x for x in APs_to_correct if x not in current_set]
        to_remove = [x for x in APs_to_correct if x in current_set]

        try:
            os.remove(os.getcwd() + '/differ.set')
            os.remove(restored_sketch_path)
            os.remove(current_set_path)
        except Exception as e:
            print(f"An error occurred while trying to remove the file '{root_path}': {str(e)}")

        reconstructed_WiFi_finger_print = list(
            set([element for element in current_set if element not in to_remove] + to_add))
        regenerated_key = self.generate_key_from_wifi_fingerprint(reconstructed_WiFi_finger_print, helper_data)
        return regenerated_key
