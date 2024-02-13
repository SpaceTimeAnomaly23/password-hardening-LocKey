import os

from location_manager import LocationManager
from scan.LocKeyManager import LocKeyManager
from util.IO import *
from util.logger import *

# Assumed min entropy per beacon frame:
BEACON_FRAME_MIN_ENTROPY = 17.6

# Lower bound key entropy for LocKey:
WANTED_KEY_ENTROPY = 76

# Scan duration for calibration:
NUMBER_OF_SCANS = 1

# Sets the strength of the master password:
MASTER_PASSWORD_BYTES = 16


def main():
    """
    Main function to manage location calibration and reconstruction.
    """
    root_path = os.getcwd()
    Logger.setLevel(logging.INFO)  # set to INFO or DEBUG

    loc_key_manager = LocKeyManager(BEACON_FRAME_MIN_ENTROPY, WANTED_KEY_ENTROPY, NUMBER_OF_SCANS)
    location_manager = LocationManager(loc_key_manager, root_path)

    # prompt user for input
    user_input = get_initial_user_input()

    if user_input == "calibrate_location":
        calibration_input = get_input_for_calibration()
        if calibration_input == "calibrate_initial_location":
            location_manager.add_initial_location(MASTER_PASSWORD_BYTES)

        elif calibration_input == "calibrate_additional_location":
            location_manager.add_additional_location()

    elif user_input == "reconstruction_scan":
        master_password = location_manager.reconstruct_location()
        # This is the returned master password from reconstructing a location specific key
        # It can be forwarded to an authentication service, like a password manager API
        if master_password is None:
            Logger.info("Failed to access master password")
        else:
            Logger.info("Master key: %s", master_password)


if __name__ == '__main__':
    main()
