# Password hardening using extracted secrets from Wi-Fi signals

This is a Python-based application for password hardening. A location specific key generated
from Wi-Fi beacon frames. This Wi-Fi key and a user password are combined using a key derivation 
function. The derived key is used to encrypt a master password, which can for authentication (e.g. a 
password manager). Access the master password is only possible when reconstructing the locations 
specific key and providing the original user password. 

This application is a proof of concept and does not provide a secure coding base in its current state.

This implementation uses the files `differ` and `sketch`, which originate from
PinSketch https://github.com/hbhdytf/PinSketch. 

## Installation
Tested on Ubuntu 22.04

Python NetworkManager requires the following Linux packages.
Using `sudo apt-get install` install the following packages:
```
build-essentials
python3-dev
libglib2.0-dev
libdbus-1-dev
pkg-config
```

Install NTL library required for LocKey mechanics:
```
sudo apt-get install libntl-dev
```

Install packages using the requirements.txt or by using:
```
pip install python-networkmanager
pip install argon2-cffi
pip install pycryptodome
```

If getting a tkinter missing dependency error, install tk with:
```
sudo apt-get install python3-tk
```

## Usage
Ensure that at least 10 to 15 access points (APs) are being detected.If the number of APs
is too low, key generation will fail due to low entropy. 

Running the main.py first calibrate the initial location. The password you enter will later be needed for key
reconstruction. Remember your password, as there is no way to restore it. 
When calibrating a new location, scanning for 3 minutes is recommended. 
Save the backup key to a notepad etc. In this implementation handling of the 
backup key is simplified, instead of using a secure two-factor authentication scheme.
A master password is generated automatically, when adding the first location. This master password acts 
as an authentication key, e.g. for a password manager. 

The master password from a calibrated location can be restored by placing the laptop in the same location 
and then running the reconstruction algorithm. Changes in the Wi-Fi environment are handled by an error
correction subroutine. However, too many changes in the Wi-Fi environment will prevent a successful key
reconstruction, requiring the use of the backup key.

Adding further locations requires the backup key in order to access the master password.


### Scanning 
Whenever a location is added, scanning takes place in the background. During scanning, the laptop
should not move. Remember the location, as restoring the key requires the laptop to be 
in that same location. 

### Beacon frame min-entropy

For BEACON_FRAME_MIN_ENTROPY see literature:
https://www.distributed-systems.net/my-data/papers/2022.etaa.pdf
https://www.distributed-systems.net/my-data/papers/2023.ispec.pdf
http://essay.utwente.nl/94293/1/Ciresica_MA_EEMCS.pdf


## License

MIT License

Copyright (c) 2023 [fullname]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.