# PowerWrist Backend Development Guide

## Overview

This guide provides detailed instructions for developers who want to create a custom backend API compatible with the PowerWrist watchOS application. PowerWrist allows users to interact with your backend through a series of prompts (choices, text inputs, integer inputs, or location requests) directly from their Apple Watch, enabling control and information retrieval without needing their iPhone nearby.

The watch app communicates with a single backend endpoint URL configured by the user via the iOS companion app. Your backend's responsibility is to receive requests, process the user's interaction state, and return the next set of prompts or final results in a specific JSON format.

## API Specification

Your backend must implement a single endpoint (the root path `/`) that responds to `GET` and `POST` HTTP requests according to the OpenAPI 3.0 specification provided separately (see `openapi.yaml`).

In summary, the API expects:

* **`GET /`**: Called for the initial load. Responds with a JSON array (`Prompt`) representing the first screen's choices/info.
* **`POST /`**: Called upon user interaction. Receives the interaction history (`State` array) in the JSON request body and responds with a new JSON array (`Prompt`) for the next screen.

The core data structures are:

* **`State` (Request Body for POST):** A JSON array of strings representing the sequence of user choices (`id` from the selected item), text inputs, integer inputs (as strings), or location inputs (as "latitude,longitude" strings).
* **`Prompt` (Response Body for GET/POST):** A JSON array of prompt objects.
* **Object within `Prompt` array:** Represents a single item displayed on the watch. Key fields include:
    * `id` (string, required): Unique identifier for this item/choice.
    * `text` (string, required): Display text (can be encrypted).
    * `icon` (string, optional): SF Symbol name.
    * `encrypted` (boolean, optional): If true, `text`, `nextPromptTitle`, `nextPromptMessage` are encrypted.
    * `nextPrompt` (string, optional, enum: `choice`, `text`, `integer`, `location`): Defines the next interaction type. If omitted, it's a final result.
    * `nextPromptProperties` (array of strings, optional, enum: `encryptText`, `requireNonEmptyText`): Modifies the behavior of the *next* text prompt.
    * `nextPromptTitle` (string, optional): Custom title for the next screen (can be encrypted).
    * `nextPromptMessage` (string, optional): Informational message for the next screen (can be encrypted).

**Refer to the `openapi.yaml` file for the formal specification.**

## Request/Response Flow

The interaction between the PowerWrist app and your backend follows these steps:

1.  **Initial Load (`GET /`)**:
    * When the app starts or the user navigates home, it sends a `GET /` request to your configured endpoint URL.
    * Your backend should respond with a `200 OK` and a JSON array (`Prompt`) representing the initial choices or information.
2.  **User Interaction (`POST /`)**:
    * If the user selects an item that has `nextPrompt` set to `choice`, `text`, `integer`, or `location`:
        * The app sends a `POST /` request to your endpoint.
        * The request body is a JSON array (`State`) containing the sequence of `id`s (for choices) and user-entered data (text, integer string, or location string) leading to this point. The `id` or data from the *most recent* interaction is the last element in the array.
        * Your backend receives this `State` array. You should parse it to understand the user's current context and desired action.
        * Based on the `State`, your backend performs the necessary logic (e.g., call another API, toggle a device, query a database).
        * Your backend responds with `200 OK` and a *new* JSON `Prompt` array representing the next screen (choices, input prompt details, or final result).
    * If the user selects an item *without* `nextPrompt` defined:
        * The app navigates to a result view which then makes one final `POST` request with the complete `State`.
        * Your backend processes this final `State` and returns a `Prompt` array containing the final result text to be displayed.
3.  **Text Input**:
    * If a selected item has `nextPrompt: "text"`, the app displays a text input screen.
    * The `nextPromptTitle` (or the original item's `text`) is used as the screen title.
    * The `nextPromptMessage` is displayed as context if provided.
    * The `nextPromptProperties` (`encryptText`, `requireNonEmptyText`) modify the input behavior.
    * When the user submits text, the app sends a `POST /` request. The submitted text becomes the last element in the `State` array sent to your backend. If `encryptText` was set, the app encrypts the text before sending it.
4.  **Integer Input**:
    * If a selected item has `nextPrompt: "integer"`, the app displays an integer input screen with a stepper.
    * The `nextPromptTitle` and `nextPromptMessage` are used if provided.
    * When the user proceeds, the app sends a `POST /` request. The selected integer, **formatted as a string**, becomes the last element in the `State` array sent to your backend.
5.  **Location Input**:
    * If a selected item has `nextPrompt: "location"`, the app attempts to access the user's current location (requesting permission if needed).
    * The `nextPromptTitle` and `nextPromptMessage` are used if provided.
    * If location access is granted and successful, the app shows the coordinate on a mini-map. When the user proceeds, the app sends a `POST /` request. The location, **formatted as a "latitude,longitude" string**, becomes the last element in the `State` array.
    * If location access is denied or fails, the user cannot proceed down this path.
6.  **Error Handling**:
    * If your backend cannot process the request or encounters an error, respond with an appropriate HTTP status code (e.g., `400 Bad Request` for invalid state, `500 Internal Server Error` for backend issues). The app will display a generic error message.

## Authentication

You can secure your backend endpoint using a custom HTTP header.

* **Configuration**: The user configures the Header Name (e.g., `X-API-Key`, `Authorization`) and Header Value (e.g., `your-secret-token`, `Bearer your-jwt`) in the PowerWrist iOS companion app.
* **Request**: The watch app automatically includes this header and value in *every* `GET` and `POST` request it sends to your backend.
* **Verification**: Your backend should check for the presence and validity of this header on incoming requests to authenticate the user/app.

## Encryption

For sensitive information, PowerWrist supports end-to-end encryption using AES-CBC with PKCS#7 padding.

* **Configuration**: The user provides a 16-byte (128-bit) AES key, encoded in Base64, via the iOS companion app. The app validates that the decoded key is exactly 16 bytes long.
* **Backend -> App Encryption**:
    * If you want to send encrypted content *to* the app, set `encrypted: true` in the prompt object(s) within your JSON response.
    * You **must** encrypt the `text` field, and optionally the `nextPromptTitle` and `nextPromptMessage` fields, using the shared AES key and AES-CBC mode.
    * **Encryption Format**: Generate a random 16-byte IV (Initialization Vector) for each encryption operation. The final encrypted string sent in the JSON must be formatted as: `Base64(IV) + ":" + Base64(Ciphertext)`.
    * The app will automatically decrypt these fields before displaying them if `encrypted: true` is set and a valid key is configured. If no key is configured or decryption fails, the app will show an error.
* **App -> Backend Encryption**:
    * If you want the user's text input to be encrypted *before* being sent to your backend, define a prompt object with `nextPrompt: "text"` and include `"encryptText"` in the `nextPromptProperties` array.
    * When the user submits text on the subsequent screen, the app will encrypt it using the configured key (same IV:Ciphertext format) and send the encrypted string as the last element in the `State` array during the `POST` request.
    * Your backend needs to parse the `State` array, identify the encrypted text entry, and decrypt it using the shared key.
* **Security Note**: While encryption adds a layer of security, ensure your backend endpoint is also protected by HTTPS. The shared AES key is stored on the user's device and synced via iCloud Keychain/WatchConnectivity.

## Backend Example (Python/Flask)

Here is an example using Python and the Flask web framework to illustrate backend logic.

```python
import base64
import json
import os
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

app = Flask(__name__)

# --- Configuration ---
# In a real app, load this securely (e.g., environment variables)
# This key MUST match the Base64 encoded key configured in the PowerWrist iOS app
SHARED_AES_KEY_B64 = "YOUR_BASE64_ENCODED_16_BYTE_AES_KEY" # e.g., "AAECAwQFBgcICQoLDA0ODw=="
API_KEY_HEADER = "X-API-Key" # Matches header name in PowerWrist iOS app
EXPECTED_API_KEY = "YOUR_SECRET_API_KEY" # Matches header value in PowerWrist iOS app

try:
    SHARED_AES_KEY = base64.b64decode(SHARED_AES_KEY_B64)
    if len(SHARED_AES_KEY) != 16:
        raise ValueError("AES Key must be 16 bytes")
except Exception as e:
    print(f"Error loading AES key: {e}. Encryption/Decryption will fail.")
    SHARED_AES_KEY = None

# --- Encryption/Decryption Helpers ---
# Matches the app's encryption format: Base64(IV):Base64(Ciphertext)
def encrypt_text(text):
    if not SHARED_AES_KEY: return None # Or raise error
    try:
        iv = get_random_bytes(AES.block_size) # 16 bytes for AES
        cipher = AES.new(SHARED_AES_KEY, AES.MODE_CBC, iv)
        padded_data = pad(text.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return f"{base64.b64encode(iv).decode('utf-8')}:{base64.b64encode(ciphertext).decode('utf-8')}"
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None # Handle error appropriately

def decrypt_text(encrypted_data):
    if not SHARED_AES_KEY: return None # Or raise error
    try:
        iv_b64, ct_b64 = encrypted_data.split(':')
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ct_b64)
        cipher = AES.new(SHARED_AES_KEY, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        # Could be invalid key, padding error, invalid format etc.
        # The app shows "Invalid Ciphertext"
        return None # Handle error appropriately

# --- Authentication Decorator ---
def require_api_key(f):
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get(API_KEY_HEADER)
        if not api_key or api_key != EXPECTED_API_KEY:
            print(f"Authentication failed. Header: {API_KEY_HEADER}, Received: {api_key}")
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    # Renaming the function name to avoid flask exception due to duplicate function names
    decorated_function.__name__ = f.__name__
    return decorated_function

# --- API Endpoint ---
@app.route('/', methods=['GET', 'POST'])
@require_api_key
def handle_request():
    if request.method == 'GET':
        # Initial request - return top-level menu
        return jsonify(get_main_menu())
    elif request.method == 'POST':
        # Subsequent request - process state
        try:
            state = request.get_json()
            if not isinstance(state, list):
                return jsonify({"error": "Invalid state format"}), 400

            print(f"Received state: {state}")
            response_prompt = process_state(state)
            return jsonify(response_prompt)

        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON body"}), 400
        except Exception as e:
            print(f"Error processing state: {e}")
            return jsonify({"error": "Internal server error"}), 500

# --- Backend Logic (Implement your specific use cases here) ---

def get_main_menu():
    """Returns the initial choices shown in the app."""
    return [
        { "id": "lights", "text": "Control Lights", "icon": "lightbulb.fill", "nextPrompt": "choice", "nextPromptTitle": "Select Room" },
        { "id": "webhook", "text": "Trigger Webhook", "icon": "bolt.fill", "nextPrompt": "choice", "nextPromptTitle": "Select Action" },
        { "id": "status", "text": "Server Status", "icon": "server.rack" }, # Final action (triggers result view)
        { "id": "secure_note", "text": "Read Secure Note", "icon": "lock.doc", "nextPrompt": "text", "nextPromptProperties": ["encryptText"], "nextPromptTitle": "Enter Password", "nextPromptMessage": "Enter password to decrypt note"},
        { "id": "thermostat", "text": "Set Thermostat", "icon": "thermometer.medium", "nextPrompt": "integer", "nextPromptTitle": "Set Temperature (°C)", "nextPromptMessage": "Adjust temperature (0-100)"},
        { "id": "check_in", "text": "Check In Location", "icon": "location.fill.viewfinder", "nextPrompt": "location", "nextPromptTitle": "Confirm Location", "nextPromptMessage": "Fetching current location..."}
    ]

def process_state(state):
    """Processes the user's interaction state and returns the next prompt."""
    if not state: # Should not happen with POST, but good to check
        return get_main_menu()

    first_step = state[0]
    current_step = state[-1] # The ID or data from the last interaction

    # Example: Simple navigation based on the first choice
    if len(state) == 1:
        if first_step == "lights":
            return get_light_rooms()
        elif first_step == "webhook":
            return get_webhook_actions()
        elif first_step == "status":
            # Final action - actually fetch status here
            status = "All systems nominal." # Replace with real logic
            return [{"id": "status_result", "text": status}]
        elif first_step == "secure_note":
             # The user selected "Read Secure Note". App shows text input.
             # Need a dummy prompt response so app knows what to do *after* text input.
             return [{"id": "submit_password", "text": "Submit Password"}] # This line won't be displayed.
        elif first_step == "thermostat":
            # The user selected "Set Thermostat". App shows integer input.
            # Need a dummy prompt response for after integer input.
            return [{"id": "submit_temperature", "text": "Set Temperature"}] # Not displayed.
        elif first_step == "check_in":
            # The user selected "Check In". App shows location prompt.
            # Need a dummy prompt response for after location is fetched.
            return [{"id": "submit_location", "text": "Confirm Check-in"}] # Not displayed.


    # Example: Handling multi-step flows (e.g., Lights -> Room)
    elif len(state) == 2 and first_step == "lights":
        selected_room = current_step
        return get_lights_in_room(selected_room)

    elif len(state) == 2 and first_step == "webhook":
        selected_webhook = current_step
        # Trigger the webhook here
        print(f"Triggering webhook: {selected_webhook}")
        result_text = f"Webhook '{selected_webhook}' triggered!"
        return [{"id": f"wh_result_{selected_webhook}", "text": result_text }]

    # Example: Handling text input (password for secure note)
    elif len(state) == 2 and first_step == "secure_note":
        # The user entered text (password), which is state[1] (current_step)
        # It should be encrypted because we set "encryptText" property
        encrypted_password = current_step
        password = decrypt_text(encrypted_password)

        if password == "correct_password": # Replace with real check
            note_content = "This is the secret note content."
            encrypted_note = encrypt_text(note_content) # Encrypt the result
            if encrypted_note:
                 return [{
                    "id": "note_content",
                    "text": encrypted_note, # Send encrypted text
                    "encrypted": True      # Tell the app to decrypt
                 }]
            else:
                return [{"id": "enc_error", "text": "Error encrypting note."}]
        else:
            return [{"id": "pw_incorrect", "text": "Password incorrect."}]

    # Example: Handling integer input (thermostat)
    elif len(state) == 2 and first_step == "thermostat":
        # The user selected an integer, which is state[1] (current_step) as a string
        temp_str = current_step
        try:
            temperature = int(temp_str)
            # Perform action with the temperature
            print(f"Setting thermostat to {temperature}°C")
            result_text = f"Thermostat set to {temperature}°C."
            return [{"id": "thermo_result", "text": result_text}]
        except ValueError:
            print(f"Invalid integer string received: {temp_str}")
            return [{"id": "thermo_error", "text": "Invalid temperature value received."}]

    # Example: Handling location input (check-in)
    elif len(state) == 2 and first_step == "check_in":
        # The user confirmed location, which is state[1] (current_step) as "lat,lon" string
        location_str = current_step
        try:
            latitude, longitude = map(float, location_str.split(','))
            # Perform action with the location
            print(f"User checked in at Latitude: {latitude}, Longitude: {longitude}")
            result_text = f"Checked in at {latitude:.4f}, {longitude:.4f}."
            # Optional: Encrypt the confirmation message
            # encrypted_result = encrypt_text(result_text)
            # return [{"id": "checkin_result", "text": encrypted_result, "encrypted": True}]
            return [{"id": "checkin_result", "text": result_text}]
        except (ValueError, IndexError):
            print(f"Invalid location string received: {location_str}")
            return [{"id": "checkin_error", "text": "Invalid location format received."}]

    # Example: Handling the light toggle (final step in lights flow)
    elif len(state) == 3 and first_step == "lights":
        room = state[1]
        light_action = current_step # e.g., "living_room_main_toggle"
        # Perform the light toggle action here
        print(f"Performing action '{light_action}' in room '{room}'")
        result_text = f"Action '{light_action}' completed."
        return [{"id": "light_result", "text": result_text}]


    # Default fallback if state is unrecognized
    else:
        print(f"Unrecognized state: {state}")
        return [{"id": "error", "text": "Sorry, I didn't understand that state."}]


# --- Specific Logic Functions (replace with your actual implementations) ---

def get_light_rooms():
    # In a real app, query your smart home system
    return [
        {"id": "living_room", "text": "Living Room", "icon": "sofa.fill", "nextPrompt": "choice", "nextPromptTitle": "Select Light/Action"},
        {"id": "kitchen", "text": "Kitchen", "icon": "fork.knife", "nextPrompt": "choice", "nextPromptTitle": "Select Light/Action"},
        {"id": "all_off", "text": "All Lights Off", "icon": "power"}, # Final Action
    ]

def get_lights_in_room(room_id):
     # In a real app, query lights for the specific room
     if room_id == "living_room":
         return [
             {"id": "living_room_main_toggle", "text": "Toggle Main Light", "icon": "lightswitch.on.fill"},
             {"id": "living_room_lamp_toggle", "text": "Toggle Lamp", "icon": "lamp.floor.fill"}
         ]
     elif room_id == "kitchen":
          return [
             {"id": "kitchen_main_toggle", "text": "Toggle Main Light", "icon": "lightswitch.on.fill"},
             {"id": "kitchen_counter_toggle", "text": "Toggle Counter LEDs", "icon": "lightstrip.2"}
         ]
     elif room_id == "all_off":
         # Perform action immediately
         print("Turning all lights off")
         return [{"id":"all_off_confirm", "text": "All lights turned off."}]
     else:
         return [{"id":"room_unknown", "text": "Unknown room."}]

def get_webhook_actions():
    # Define your webhook actions
    return [
        {"id": "ifttt_movie_mode", "text": "Movie Mode (IFTTT)", "icon": "film.fill"},
        {"id": "start_backup", "text": "Start Server Backup", "icon": "externaldrive.badge.icloud"},
    ]


if __name__ == '__main__':
    # Use 0.0.0.0 to make it accessible on your network
    # Ensure firewall allows access on port 5001
    # Use HTTPS in production! (e.g., behind a reverse proxy like Nginx)
    app.run(host='0.0.0.0', port=5001, debug=True)
