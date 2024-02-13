CHOICES = {
    1: "calibrate_location",
    2: "reconstruction_scan",
    3: "calibrate_initial_location",
    4: "calibrate_additional_location",
    5: "test_location_quality"

}


def get_initial_user_input():
    while True:
        # Get user input and remove leading/trailing whitespace
        user_input = int(input(
            "Enter 1 for calibration \n"
            "Enter 2 for reconstruction \n"
            ">>> "
        ).strip())

        if user_input in (1, 2):
            return CHOICES.get(user_input)  # Return the valid input
        else:
            print("Invalid input. Please enter 1 or 2.")


def get_input_for_calibration():
    while True:
        # Get user input and remove leading/trailing whitespace
        user_input = int(input(
            "Enter 3 for initial location \n"
            "Enter 4 for additional location \n"
            ">>> "
        ).strip())

        if user_input in (3, 4):
            return CHOICES.get(user_input)  # Return the valid input
        else:
            print("Invalid input. Please enter 3 or 4.")
