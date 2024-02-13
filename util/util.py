import json


def flatten(list_in):
    """
    Takes a list of lists and converts it into a single, one-dimensional list
    """
    return [item for sublist in list_in for item in sublist]


def parse_file_to_json_dict(file_path: str, key_name: str):
    with open(file_path, 'r') as file:
        file_contents = file.read()
    json_dict = json.dumps({key_name: file_contents})
    return json_dict


def save_to_file_from_json_dict(json_dict: str, json_key_name: str, file_path: str):
    content = json.loads(json_dict)[json_key_name]
    with open(file_path, 'w') as new_file:
        # Write the extracted contents to the new file
        new_file.write(content)
