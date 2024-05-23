import os,glob,datetime,argparse
import base64,json
import hashlib,codecs,struct
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from pypush_gsa_icloud import icloud_login_mobileme, generate_anisette_headers
import time
import datetime
import os

from generate_keys import get_both_public_keys

initialState = { 
    "length": 16,
    "complete": False,
    "first_bit_time": None,
    "last_bit_time": None,
    "message": "",
    "content":[{"char": None, "bits": [None]*8, "keys": [], "res_keys": []} for _ in range(16)]
    }

def getAuth(regenerate=False, second_factor='sms'):
    CONFIG_PATH = os.path.dirname(os.path.realpath(__file__)) + "/auth.json"
    if os.path.exists(CONFIG_PATH) and not regenerate:
        with open(CONFIG_PATH, "r") as f: j = json.load(f)
    else:
        mobileme = icloud_login_mobileme(second_factor=second_factor)
        j = {'dsid': mobileme['dsid'], 'searchPartyToken': mobileme['delegates']['com.apple.mobileme']['service-data']['tokens']['searchPartyToken']}
        with open(CONFIG_PATH, "w") as f: json.dump(j, f)
    return (j['dsid'], j['searchPartyToken'])

def init_state(modem_id, msg_id):
    state = initialState  
    total_key_counter = 0
    character_counter = 0
    
    # Iterate through characters in the state content
    for character in state["content"]:
        public_keys = []
        # Generate 8 pairs of public keys for each character
        for key in range(8):
            public_key1, public_key2 = get_both_public_keys(modem_id, total_key_counter, msg_id)
            double_keys = [public_key1, public_key2]
            public_keys.append(double_keys)
            total_key_counter += 1
        # Assign generated public keys to the character
        state["content"][character_counter]['keys'] = public_keys
        character_counter += 1
    return state

def request_reports(hashed_adv_key1, hashed_adv_key2, time_window_minutes):
    unix_epoch = int(datetime.datetime.now().strftime('%s'))
    unix_epoch_ms = int(datetime.datetime.now().timestamp() * 1000)
    start_date = unix_epoch - (60 * time_window_minutes) 
    start_date_ms = unix_epoch_ms - (60 * 1000 * time_window_minutes) 

    # Function to check if report is within the specified time frame
    def is_within_timeframe(entry):
        return entry['datePublished'] >= start_date_ms

    data = {"search": [{"startDate": start_date * 1000, "endDate": unix_epoch * 1000, "ids": [hashed_adv_key1, hashed_adv_key2]}]}
    
    try:
        # Continuously fetch reports until one is found within the time frame
        while True:
            r = requests.post("https://gateway.icloud.com/acsnservice/fetch",
                            auth=getAuth(regenerate=args.regen, second_factor='trusted_device' if args.trusteddevice else 'sms'),
                            headers=generate_anisette_headers(),
                            json=data)
            res = json.loads(r.content.decode())['results']
            filtered_res = list(filter(is_within_timeframe, res))
            if len(filtered_res) == 0:
                return ""
            else: 
                return filtered_res[-1]['id']
    except Exception as e:
        print(f"An error occurred: {e}")

# Function to extract keys from reports
def keys_from_reports(reports):
    keys = [report['id'] for report in reports]
    return keys

def check_message_length(state):
    message_length = 0
    # Iterate through each character in the state
    for character in state["content"]:
        # Check if there's at least one non-None value in the 'bits' array
        if any(bit is not None for bit in character["bits"]):
            message_length += 1
    if message_length == 0:
        return 16
    else:
        return message_length

def combine_message(state):
    # Combine all characters in 'content' where the character is not None
    combined_message = ''.join([char["char"] for char in state["content"] if char["char"] is not None])
    # Update the 'message' field in the state dictionary with the combined message
    state["message"] = combined_message

def validate_message(state):
    # Get the length of the message from the 'check_message_length' function
    message_length = check_message_length(state)
    # Update the 'length' field in the state dictionary with the length of the message
    state["length"] = message_length
    
    # Count the number of characters in 'content' that are not None
    complete_chars = sum(1 for item in state['content'] if item['char'] is not None)
    
    # If there are exactly 16 complete characters, mark the length as 16 and return True
    if complete_chars == 16:
        state["length"] = 16
        return True
    else:
        # If the number of complete characters matches the expected length the message is complete
        #if complete_chars == state['length'] and all(bit == 0 for bit in state["content"][message_length-1]["bits"]) == True:
        if complete_chars == state['length']:
            state["length"] = message_length-1
            return True
        else: 
            # If the number of complete characters doesn't match the expected length the message is not complete yet
            return False

def update_state(state, time_window_hours, message_id):
    os.system("printf '\033c'")
    print()
    print("Receiving Message for ID: ", message_id)
    print()
    # loop through every character in the message (initial 16)
    character_counter = 0
    for character in range(16):
        current_time = datetime.datetime.now()
        character = state["content"][character_counter]
        #print("requesting character: ", character_counter)
        #interate through every bot in the character (8)
        for key_counter, keypair in enumerate(character["keys"]):
            # only request the bits that are still None
            if character["bits"][key_counter] == None:
                #print("requesting bit: ", key_counter)
                found_key = request_reports(keypair[0], keypair[1], time_window_hours)
                #print(found_key)
                if found_key == keypair[0]:
                    state["content"][character_counter]["bits"][key_counter] = 0
                    state["content"][character_counter]["res_keys"].append(found_key)
                    if state["first_bit_time"] is None:
                        state["first_bit_time"] = current_time
                    state["last_bit_time"] = current_time
                    #print("this key is it:",keypair[0])
                    #print("this is 0")
                elif found_key == keypair[1]:
                    state["content"][character_counter]["bits"][key_counter] = 1
                    state["content"][character_counter]["res_keys"].append(found_key)
                    if state["first_bit_time"] is None:
                        state["first_bit_time"] = current_time
                    state["last_bit_time"] = current_time
                    #print("this key is it:",keypair[1])
                    #print("this is 1")
        if None not in state["content"][character_counter]["bits"]:
            #print("all bits complete -> decode character")
            character_string = decode_char(state["content"][character_counter]["bits"])
            print(character_string)
            state["content"][character_counter]["char"] = character_string
            #print(character, end='', flush=True)

        else:
            print(state["content"][character_counter]["bits"])
        character_counter += 1
    state["complete"] = validate_message(state)

    if state["complete"]:
        combine_message(state)
    return state

def decode_char(bits):
    byte_value = int(''.join(map(str, bits)), 2)
    character = chr(byte_value)
    return character

def hex_type(x):
    return int(x, 16)

if __name__ == "__main__":
    os.environ['Test'] = '1312'
    parser = argparse.ArgumentParser()
    parser.add_argument('-M', '--minutes', help='Only show reports not older than these minutes', type=int, default=60)  # Defaulting to 60 minutes for 1 hour
    parser.add_argument('-r', '--regen', help='regenerate search-party-token', action='store_true')
    parser.add_argument('-i', '--message_id', help='message id to request', type=int, default=0)
    parser.add_argument('-t', '--trusteddevice', help='use trusted device for 2FA instead of SMS', action='store_true')
    parser.add_argument('-d', '--modem_id', help='Modem ID to use for communication', type=hex_type, default=0x11111111)
    args = parser.parse_args()

    start_time = datetime.datetime.now()

    state = init_state(args.modem_id, args.message_id)

    while True:
        if not state["complete"]:
            updated_state = update_state(state, args.minutes, args.message_id)
        else:
            end_time = datetime.datetime.now() 
            duration = end_time - start_time

            # Calculate minutes and seconds
            total_seconds = int(duration.total_seconds())
            minutes = total_seconds // 60  
            seconds = total_seconds % 60 

            print()
            print("MESSAGE COMPLETE:")
            print("-> Modem ID:", hex(args.modem_id))
            print("-> Message ID:", args.message_id)
            print("-> Length:", state["length"])
            print("-> Content:", state["message"])
            print("App started at:", start_time.strftime('%Y-%m-%d %H:%M:%S'))
            print(f"Runtime app: {minutes} minutes {seconds} seconds")
            print("First bit received at:", state["first_bit_time"].strftime('%Y-%m-%d %H:%M:%S') if state["first_bit_time"] else "N/A")
            print("Last bit received at:", state["last_bit_time"].strftime('%Y-%m-%d %H:%M:%S') if state["last_bit_time"] else "N/A")

            time_difference = state["last_bit_time"] - state["first_bit_time"]
            minutes, seconds = divmod(time_difference.total_seconds(), 60)
            print(f"Time between first and last bit: {int(minutes)} minutes and {int(seconds)} seconds")
            print()
            break
