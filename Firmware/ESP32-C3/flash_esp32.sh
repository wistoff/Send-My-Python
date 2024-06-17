#!/bin/bash


# Directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Defaults: Directory for the virtual environment
VENV_DIR="$SCRIPT_DIR/venv"

# Defaults: Serial port to access the ESP32
PORT=/dev/ttyS0

# Defaults: Fast baud rate
BAUDRATE=460800

# Parameter parsing
while [[ $# -gt 0 ]]; do
    KEY="$1"
    case "$KEY" in
        -p|--port)
            PORT="$2"
            shift
            shift
        ;;
        -s|--slow)
            BAUDRATE=115200
            shift
        ;;
        -v|--venvdir)
            VENV_DIR="$2"
            shift
            shift
        ;;
        -h|--help)
            echo "flash_esp32.sh - Flash the Send My firmware onto an ESP32 module"
            echo ""
            echo "  This script will create a virtual environment for the required tools."
            echo ""
            echo "Call: flash_esp32.sh [-p <port>] [-v <dir>] [-s]"
            echo ""
            echo "Optional Arguments:"
            echo "  -h, --help"
            echo "      Show this message and exit."
            echo "  -p, --port <port>"
            echo "      Specify the serial interface to which the device is connected."
            echo "  -s, --slow"
            echo "      Use 115200 instead of 921600 baud when flashing."
            echo "      Might be required for long/bad USB cables or slow USB-to-Serial converters."
            echo "  -v, --venvdir <dir>"
            echo "      Select Python virtual environment with esptool installed."
            echo "      If the directory does not exist, it will be created."
            exit 1
        ;;
        *)
            echo "Got unexpected parameter $1"
            exit 1
        ;;
    esac
done

# Sanity check: Port
if [[ ! -e "$PORT" ]]; then
    echo "$PORT does not exist, please specify a valid serial interface with the -p argument"
    exit 1
fi

# Setup the virtual environment
if [[ ! -d "$VENV_DIR" ]]; then
    # Create the virtual environment
    PYTHON="$(which python3)"
    if [[ -z "$PYTHON" ]]; then
        PYTHON="$(which python)"
    fi
    if [[ -z "$PYTHON" ]]; then
        echo "Could not find a Python installation, please install Python 3."
        exit 1
    fi
    if ! ($PYTHON -V 2>&1 | grep "Python 3" > /dev/null); then
        echo "Executing \"$PYTHON\" does not run Python 3, please make sure that python3 or python on your PATH points to Python 3"
        exit 1
    fi
    if ! ($PYTHON -c "import venv" &> /dev/null); then
        echo "Python 3 module \"venv\" was not found."
        exit 1
    fi
    $PYTHON -m venv "$VENV_DIR"
    if [[ $? != 0 ]]; then
        echo "Creating the virtual environment in $VENV_DIR failed."
        exit 1
    fi
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip
    pip install esptool
    if [[ $? != 0 ]]; then
        echo "Could not install Python 3 module esptool in $VENV_DIR";
        exit 1
    fi
else
    source "$VENV_DIR/bin/activate"
fi

# Call esptool.py. Errors from here on are critical
set -e

# # Clear NVM
# esptool.py --after no_reset \
#     erase_region 0x9000 0x5000
# esptool.py --before no_reset --baud $BAUDRATE \
#     write_flash 0x1000  "$SCRIPT_DIR/build/bootloader/bootloader.bin" \
#                 0x8000  "$SCRIPT_DIR/build/partition_table/partition-table.bin" \
#                 0x10000 "$SCRIPT_DIR/build/openhaystack.bin"



# Erase the specified region and then hard reset
esptool.py --after hard_reset --port "$PORT" erase_region 0x9000 0x5000

# Wait for a short period to ensure the ESP32 has reset
sleep 2

# Flash the new firmware with a default reset before flashing
# esptool.py --chip esp32c3 --before default_reset --baud $BAUDRATE --port "$PORT" \
#     write_flash 0x1000  "$SCRIPT_DIR/build/bootloader/bootloader.bin" \
#                 0x8000  "$SCRIPT_DIR/build/partition_table/partition-table.bin" \
#                 0x10000 "$SCRIPT_DIR/build/openhaystack.bin"


# Flash bootloader, partition table, and application firmware
esptool.py --chip esp32c3 --port "$PORT" --baud "$BAUDRATE" \
           --before=default_reset --after=hard_reset \
           write_flash --flash_mode dio --flash_freq 40m --flash_size 2MB \
           0x0 "$SCRIPT_DIR/build/bootloader/bootloader.bin" \
           0x10000 "$SCRIPT_DIR/build/openhaystack.bin" \
           0x8000 "$SCRIPT_DIR/build/partition_table/partition-table.bin"