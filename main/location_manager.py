import binascii
import copy
import json
import os
import secrets
import threading
from secrets import token_urlsafe
from tkinter import Tk, simpledialog

from crypto.AES import AES_encrypt, AES_decrypt
from crypto.argon_2 import kdf_argon2
from scan.LocKeyManager import LocKeyManager
from util.logger import Logger
from util.util import parse_file_to_json_dict


def enter_password(password_result):
    """
    Input window for password. Called by the password_thread. The password_result is returned to the thread directly
    """
    root = Tk()
    root.withdraw()  # Hide the main window
    user_input = simpledialog.askstring("USER PASSWORD", "Choose password:")
    root.destroy()
    password_result.append(user_input)


class LocationManager:
    """
    Manages the initialization, addition and reconstruction of a master password using LocKey.
    """

    def __init__(self, loc_key_manager: LocKeyManager, root_path: str):

        self.root_path = root_path
        self.loc_key_manager = loc_key_manager
        self.encrypted_locations = []
        self.load_encrypted_locations()

    def load_encrypted_locations(self):
        """
        Load encrypted locations from the file.
        """
        vault_path = os.getcwd() + '/vault/location_data'
        if os.path.getsize(vault_path) == 0:
            print(f"The file {vault_path} is empty.")
        else:
            with open(vault_path, 'r') as file:
                # Read all lines into a list
                encrypted_entries = [line.strip() for line in file.readlines()]
                self.encrypted_locations = encrypted_entries

    def add_initial_location(self, master_password_length: int) -> None:
        """
        This procedure calibrates the first location for password vault using LocKey.
        The initial and the backup cipher are created and stored in the password vault.
        """
        # check that no encrypted_locations exist already
        if not self.encrypted_locations:
            # Create a thread for enter_password function
            password_result = []
            password_thread = threading.Thread(target=enter_password, args=(password_result,))
            password_thread.start()
            # Scan and generate Wi-Fi fingerprint while password window is up
            hashed_beacon_frame_data = self.loc_key_manager.calibration_scan()
            password_thread.join()
            Logger.debug("User Password: %s", password_result)

            # Generate WiFi fingerprint
            if self.loc_key_manager.check_entropy(hashed_beacon_frame_data):
                self.loc_key_manager.create_secure_sketch()
            else:
                Logger.info("The location does not proved enough entropy")
                return

            # Generate master password and backup factor
            master_password = token_urlsafe(master_password_length)
            self.add_backup_factor(master_password)

            # LocKey: Generate helper data and key
            helper_data_coefficients = self.generate_helper_data_coefficients()
            loc_key = self.loc_key_manager.generate_key_from_wifi_fingerprint(
                self.loc_key_manager.valid_ap_shakes, helper_data_coefficients)

            # Argon-2
            argon2_key, argon2_salt = kdf_argon2(password_result[0], str(loc_key))

            # AES
            AES_ciper = AES_encrypt(argon2_key, master_password)

            # Packing and combining everything into JSON-format for storage
            initial_location_ciper = json.loads(AES_ciper)
            initial_location_ciper['argon2_salt'] = argon2_salt.decode("utf-8")
            initial_location_ciper['coefficients'] = helper_data_coefficients
            secure_sketch = json.loads(parse_file_to_json_dict(os.getcwd() + '/sets/template.ss', 'sketch'))
            initial_location_ciper = json.dumps({**initial_location_ciper, **secure_sketch})
            # Add and save location
            self.encrypted_locations.append(initial_location_ciper)
            self.save_encrypted_locations()

            # Reset and remove stuff
            self.remove_sets()
            self.loc_key_manager.valid_ap_shakes = {}

        else:
            Logger.info("Existing locations found. Returning to main menu...")
            return

    def add_additional_location(self) -> None:
        """
        This procedure adds a location to an already existing LocKey vault.
        """
        if len(self.encrypted_locations) == 0:
            Logger.info("Location list is empty. Create initial location first")
            return
        # # Get master password using backup key
        master_password = self.use_backup_factor()
        if not master_password:
            Logger.warning("Incorrect Backup Key")
            return

        # Create a thread for enter_password function
        password_result = []
        password_thread = threading.Thread(target=enter_password, args=(password_result,))
        password_thread.start()
        # Scan and generate Wi-Fi fingerprint while password window is up
        hashed_beacon_frame_data = self.loc_key_manager.calibration_scan()
        password_thread.join()
        Logger.debug("User Password: %s", password_result)

        # Generate WiFi fingerprint
        if self.loc_key_manager.check_entropy(hashed_beacon_frame_data):
            self.loc_key_manager.create_secure_sketch()
        else:
            Logger.info("The location does not proved enough entropy")
            return

        # LocKey: Generate helper data and key
        helper_data_coefficients = self.generate_helper_data_coefficients()
        loc_key = self.loc_key_manager.generate_key_from_wifi_fingerprint(
            self.loc_key_manager.valid_ap_shakes, helper_data_coefficients)

        # Argon-2
        argon2_key, argon2_salt = kdf_argon2(password_result[0], str(loc_key))

        # AES
        AES_ciper = AES_encrypt(argon2_key, master_password)
        if AES_ciper is None:
            return

        # Packing and combining everything into JSON-format for storage
        initial_location_ciper = json.loads(AES_ciper)
        initial_location_ciper['argon2_salt'] = argon2_salt.decode("utf-8")
        initial_location_ciper['coefficients'] = helper_data_coefficients
        secure_sketch = json.loads(parse_file_to_json_dict(os.getcwd() + '/sets/template.ss', 'sketch'))
        initial_location_ciper = json.dumps({**initial_location_ciper, **secure_sketch})
        # Add and save location
        self.encrypted_locations.append(initial_location_ciper)
        self.save_encrypted_locations()

        # Reset and remove stuff
        self.remove_sets()
        self.loc_key_manager.valid_ap_shakes = {}

    def reconstruct_location(self):
        """
        This function tries to reconstruct the master password from the vault with user-password and LocKey as
        inputs. \n

        Access location data using: location_data[index]["KEYWORD"] \n
        Keywords: nonce, ciphertext, tag, argon2_salt, sketch

        :return: Currently, nothing is returned, but can be modified to return the decrypted master password.
        """
        NUMBER_OF_RECONSTRUCTION_SCANS = 1
        if not self.encrypted_locations:
            Logger.info("Found no locations to reconstruct")
            return

        # Load encrypted locations
        encrypted_location_data = []
        for line in self.encrypted_locations:
            encrypted_location_data.append(json.loads(line))

        # Create a thread for enter_password function
        password_result = []
        password_thread = threading.Thread(target=enter_password, args=(password_result,))
        password_thread.start()
        password_thread.join()
        Logger.debug("User Password: %s", password_result)

        # Regenerate key trying all encrypted locations
        searching = True
        counter = 0
        WAIT_MAX = 100
        while searching:
            hashed_beacon_frame_data = self.loc_key_manager.calibration_scan(NUMBER_OF_RECONSTRUCTION_SCANS)
            # Generate WiFi fingerprint
            if self.loc_key_manager.check_entropy(hashed_beacon_frame_data, NUMBER_OF_RECONSTRUCTION_SCANS):
                self.loc_key_manager.create_secure_sketch()
            counter += 1
            if counter > WAIT_MAX:
                searching = False
            for loc in encrypted_location_data:
                # skips backup factor encryption
                if "sketch" not in loc:
                    continue
                # Load helper data and secure sketch
                location = copy.deepcopy(loc)
                helper_data_coefficients = location.pop("coefficients")
                secure_sketch = location.pop("sketch")
                argon2_salt = location.pop("argon2_salt")
                # Only AES fields left in location
                AES_cipher = location

                # Write secure sketch to file since NTL-lib requires file input
                with open(os.getcwd() + "/sets/restored.ss", "w") as file:
                    file.write(secure_sketch)
                self.loc_key_manager.create_template("/current.set")

                # LocKey reconstruct key with restored helper data
                reconstructed_loc_key = self.loc_key_manager.reconstruct_key(helper_data_coefficients)

                # Argon-2
                argon2_salt = argon2_salt.encode("utf-8")
                argon2_key, _ = kdf_argon2(password_result[0], str(reconstructed_loc_key), argon2_salt)
                master_password = AES_decrypt(argon2_key, AES_cipher)
                if master_password:
                    self.remove_sets()
                    return master_password

            # Reset and remove stuff
            self.remove_sets()
            self.loc_key_manager.valid_ap_shakes = {}
        Logger.info("Access failed. using backup factor...")
        return self.use_backup_factor()

    def add_backup_factor(self, master_password: str) -> None:
        """
        Adds an 256-bit AES backup encryption of the master password to 'encrypted_locations'. It can only be accessed
        using the backup key.

        :param master_password: The password to be encrypted with the backup key
        """

        backup_key = secrets.token_bytes(32)
        hexadecimal_string = binascii.hexlify(backup_key).decode()
        input(
            "This is your backup key. Store it somewhere safe! \n" + "\033[94m" + str(hexadecimal_string) + "\033[0m" +
            "\npress ENTER to continue")
        backup_cipher = AES_encrypt(backup_key, master_password)
        self.encrypted_locations.append(backup_cipher)
        self.save_encrypted_locations()

    def use_backup_factor(self):
        """
        Prompts the user to input a backup key through an input dialog.
        If the correct backup key is provided, this function uses AES decryption
        to decrypt the master password for the given location.

        :return: If successful, returns the decrypted master password, else returns 'None'.
        """
        root = Tk()
        root.withdraw()  # Hide the main window
        backup_key = simpledialog.askstring("BACKUP KEY", "Enter backup key")
        root.destroy()
        if backup_key is None:
            Logger.warning("No backup key was entered. Exiting program...")
            return
        # Load encrypted locations
        encrypted_location_data = []
        for line in self.encrypted_locations:
            encrypted_location_data.append(json.loads(line))

        for location in encrypted_location_data:
            # only check backup factor encryption
            if "sketch" in location:
                continue
            master_password = AES_decrypt(bytes.fromhex(backup_key), location)
            if master_password:
                return master_password

    def save_encrypted_locations(self) -> None:
        """
        Saves encrypted_locations to file. This file acts a password vault.
        """
        vault_path = os.getcwd() + '/vault/location_data'
        with open(vault_path, 'w') as file:
            for entry in self.encrypted_locations:
                file.write(entry + '\n')
        Logger.info("Encrypted locations saved to /vault/location_data")

    def generate_helper_data_coefficients(self) -> tuple[int, int]:
        """
        Generates helper data coefficients that are needed by LocKey

        :return: Tuple of coefficients a and b.
        """

        # generate random coefficients mod p
        coefficient_a = 0
        while coefficient_a == 0:
            coefficient_a = int.from_bytes(os.urandom(17), "little") % self.loc_key_manager.PRIME_MODULUS
        coefficient_b = int.from_bytes(os.urandom(17), "little") % self.loc_key_manager.PRIME_MODULUS
        return coefficient_a, coefficient_b

    def remove_sets(self):
        """
        Removes the file template.ss
        """
        try:
            os.remove(os.getcwd() + '/sets/template.ss')
        except Exception as e:
            Logger.debug(f"An error occurred while trying to remove the file '{os.getcwd()}': {str(e)}")
