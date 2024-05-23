# SendMy Python

Send My Python is a Python implementation of the SendMy Code by [@positive-security](https://github.com/positive-security).
The original [SendMy](https://github.com/positive-security/send-my) Code allows you to upload abritrary data from devices without an internet connection by (ab)using Apple's Find My network. The data is broadcasted via Bluetooth Low Energy and forwarded by nearby Apple devices. In the original code the data is retrieved using a datafetcher and an Apple Mail plugin. This Code uses an anisette-v3-server and Python script to receive the message. 

The application consists of two parts:
- Firmware: An ESP32 firmware that turns the microcontroller into a serial (upload only) modem (unchanged from the original source Code)
- DataFetcher: A python script that makes use of an anisette-v3-server to retrieve, decode and display the uploaded data in the terminal


The parts are based on [FindMy]([https://github.com/biemster/FindMy]) by [@biemster](https://github.com/biemster),  [OpenHaystack](https://github.com/seemoo-lab/openhaystack) by [@seemoo-lab](https://github.com/seemoo-lab) and [SendMy](https://github.com/positive-security/send-my) by [@positive-security](https://github.com/positive-security). This README is also based on original repo by [@positive-security](https://github.com/positive-security). 

# How it works

Summary: When sending, the data is encoded in the public keys that are broadcasted by the microcontroller. Nearby Apple devices will pick up those broadcasts and forward the data to an Apple backend as part of their location reporting. Those reports can later be retrieved by any device to decode the sent data.

Check https://positive.security/blog/send-my for details.

# How to setup
## Prerequiries
- Apple ID: Free Apple ID is required, with SMS 2FA properly setup. If you don't have any, follow one of the many guides found on the internet.
- Docker
- Anaconda

## Setup annisete-v3-server
1. Clone `anisette-v3-server` repository into this repository:
```bash
git clone https://github.com/Dadoum/anisette-v3-server
```
2. Run `anisette-v3-server`inside of docker using the following command.
```bash
docker run -d --restart always --name anisette-v3 -p 6969:6969 --volume anisette-v3_data:/home/Alcoholic/.config/anisette-v3/lib/ dadoum/anisette-v3-server
```
3. Confirm that anisette-v3-server is running by visiting: http://localhost:6969/ in your browser.

## Setup conda env
1. set up the conda enviroment using the yml file (requieres anaconda installed)
`conda env create -f conda-environment.yml`
2. activate the created conda env
`conda activate sendmy`

# How to run

## The Modem

1. Change the `modem_id` (and if desired the `data_to_send` default message) in the openhaystack_main.c
2. Check [the Firmware README.md](Firmware/ESP32/README.md) for flashing instructions
3. After boot, the ESP32 will immediately broadcast the default message in a loop until a new message is received via the serial interface. Messages can be sent to the modem e.g. using the Arduino IDE's Serial Monitor.

## The Python Data Fetcher

1. `cd` into the `'SendMy Python'` directory 
2. start the script with the previously set modem_id and the message_id you want to receive `python request_message.py --message_id 0  --modem_id 0x00000001` 
3. additional settings ``--minutes`` defines the timeframe, ``--trusteddevice`` use trusted device for 2FA instead of SMS
3. The script will iterate through each of the 16 characters, displaying their corresponding 8-bit arrays. Once a full set of 8 bits is accumulated, it will convert them into their respective character. The script will continue this process until the entire message is complete.

# License
SendMy Python is licensed under the GNU Affero General Public License v3.0, consistent with the licensing of "OpenHaystack," which is also under the same license.