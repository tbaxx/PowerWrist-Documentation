# PowerWrist Backend Development Guide

## Overview

This guide provides detailed instructions for developers who want to create a custom backend API compatible with the PowerWrist watchOS application. PowerWrist allows users to interact with your backend through a series of prompts (choices, text inputs, integer inputs, location requests, confirmations, or multiple choice selections) directly from their Apple Watch, enabling control and information retrieval without needing their iPhone nearby.

The watch app communicates with a single backend endpoint URL configured by the user via the iOS companion app. Your backend's responsibility is to receive requests, process the user's interaction state, and return the next set of prompts or final results in a specific JSON format.

## API Specification

Your backend must implement a single endpoint (the root path `/`) that responds to `GET` and `POST` HTTP requests according to the OpenAPI 3.0 specification provided separately (see `openapi.yaml`).

In summary, the API expects:

* **`GET /`**: Called for the initial load. Responds with a JSON array (`Prompt`) representing the first screen's choices/info.
* **`POST /`**: Called upon user interaction. Receives the interaction history (`State` array) in the JSON request body and responds with a new JSON array (`Prompt`) for the next screen.

The core data structures are:

* **`State` (Request Body for POST):** A JSON array of strings representing the sequence of user choices (`id` from the selected item), text inputs, integer inputs (as strings), location inputs (as "latitude,longitude" strings), an empty string for confirmations, or a string of '&'-separated sorted IDs for multiple choice selections.
* **`Prompt` (Response Body for GET/POST):** A JSON array of prompt objects.
* **Object within `Prompt` array:** Represents a single item displayed on the watch. Key fields include:
    * `id` (string, required): Unique identifier for this item/choice.
    * `text` (string, required): Display text (can be encrypted).
    * `icon` (string, optional): SF Symbol name.
    * `encrypted` (boolean, optional): If true, `text`, `nextPromptTitle`, `nextPromptMessage` are encrypted.
    * `nextPrompt` (string, optional, enum: `choice`, `text`, `integer`, `location`, `confirm`, `multiChoice`): Defines the next interaction type. If omitted, it's a final result.
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
    * If the user selects an item that has `nextPrompt` set to `choice`, `text`, `integer`, `location`, `confirm`, or `multiChoice`:
        * The app sends a `POST /` request to your endpoint.
        * The request body is a JSON array (`State`) containing the sequence of `id`s (for choices) and user-entered data (text, integer string, location string, empty string for confirm, '&'-separated ID string for multiChoice) leading to this point. The data from the *most recent* interaction is the last element in the array.
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
    * If a selected item has `nextPrompt: "location"`, the app attempts to access the user's current location.
    * The `nextPromptTitle` and `nextPromptMessage` are used if provided.
    * If location access is granted and successful, the app shows the coordinate on a mini-map. When the user proceeds, the app sends a `POST /` request. The location, **formatted as a "latitude,longitude" string**, becomes the last element in the `State` array.
    * If location access fails, the user cannot proceed down this path.
6.  **Confirmation**:
    * If a selected item has `nextPrompt: "confirm"`, the app displays a confirmation screen usually showing the text of the item that led to it, possibly with a custom `nextPromptTitle` or `nextPromptMessage`.
    * When the user taps the "Next" button, the app sends a `POST /` request. An **empty string (`""`)** becomes the last element in the `State` array sent to your backend, representing the confirmation action.
7.  **Multiple Choice Input**:
    * If a selected item has `nextPrompt: "multiChoice"`, the app displays a list of choices provided by the backend (as the `Prompt` array in the response to the previous step).
    * The `nextPromptTitle` and `nextPromptMessage` are used if provided.
    * The user can select one or more items from the list.
    * When the user proceeds (by tapping "Next" which appears after selecting at least one item), the app sends a `POST /` request. The IDs of the selected items, **sorted alphabetically and joined by an ampersand ('&')**, become the last element in the `State` array sent to your backend (e.g., "item1&item3&item4").
    * **Important:** The *first* item in the `Prompt` array originally sent by the backend for the multi-choice screen defines the subsequent navigation path (its `nextPrompt`, `nextPromptTitle`, etc. are used), regardless of whether that specific first item was actually selected by the user. Your backend logic needs to account for receiving the multi-choice response (the '&'-separated string) when the `state` array includes the ID of that *first* multi-choice option.
8.  **Error Handling**:
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

Here is an example using Python and the Flask web framework to illustrate backend logic. Please install [Flask](https://pypi.org/project/Flask/) and [pycryptodome](https://pypi.org/project/pycryptodome/) to use it. Also, make sure to set appropriate values for the configuration settings at the top of the script.

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
        { "id": "webhook", "text": "Trigger Webhook", "icon": "bolt.fill", "nextPrompt": "confirm", "nextPromptTitle": "Confirm Trigger?", "nextPromptMessage": "Trigger the main webhook?"},
        { "id": "status", "text": "Server Status", "icon": "server.rack" }, # Final action (triggers result view)
        { "id": "secure_note", "text": "Read Secure Note", "icon": "lock.doc", "nextPrompt": "text", "nextPromptProperties": ["encryptText"], "nextPromptTitle": "Enter Password", "nextPromptMessage": "Enter password to decrypt note"},
        { "id": "thermostat", "text": "Set Thermostat", "icon": "thermometer.medium", "nextPrompt": "integer", "nextPromptTitle": "Set Temperature (°C)", "nextPromptMessage": "Adjust temperature (0-100)"},
        { "id": "check_in", "text": "Check In Location", "icon": "location.fill.viewfinder", "nextPrompt": "location", "nextPromptTitle": "Confirm Location", "nextPromptMessage": "Fetching current location..."},
        { "id": "select_features", "text": "Select Features", "icon": "checklist", "nextPrompt": "multiChoice", "nextPromptTitle": "Choose Features", "nextPromptMessage": "Select features to enable"}
    ]

def process_state(state):
    """Processes the user's interaction state and returns the next prompt."""
    if not state: # Should not happen with POST, but good to check
        return get_main_menu()

    first_step = state[0]
    current_step_data = state[-1] # The ID or data from the last interaction

    # Example: Simple navigation based on the first choice
    if len(state) == 1:
        if first_step == "lights":
            return get_light_rooms()
        elif first_step == "webhook":
             # User selected "Trigger Webhook", app shows confirmation prompt.
             # Return dummy prompt for *after* confirmation.
             return [{"id": "trigger_webhook_confirmed", "text": "Webhook Triggered"}] # Text not displayed
        elif first_step == "status":
            # Final action - actually fetch status here
            status = "All systems nominal." # Replace with real logic
            return [{"id": "status_result", "text": status}]
        elif first_step == "secure_note":
             # User selected "Read Secure Note". App shows text input.
             return [{"id": "submit_password", "text": "Submit Password"}] # Not displayed.
        elif first_step == "thermostat":
            # User selected "Set Thermostat". App shows integer input.
            return [{"id": "submit_temperature", "text": "Set Temperature"}] # Not displayed.
        elif first_step == "check_in":
            # User selected "Check In". App shows location prompt.
            return [{"id": "submit_location", "text": "Confirm Check-in"}] # Not displayed.
        elif first_step == "select_features":
             # User selected "Select Features". Return options for multi-choice.
             return get_feature_options()


    # Example: Handling multi-step flows
    elif len(state) == 2:
        if first_step == "lights":
            selected_room = current_step_data
            return get_lights_in_room(selected_room)
        elif first_step == "webhook":
            # User confirmed the webhook trigger (current_step_data == "")
            if current_step_data == "":
                # Trigger the webhook here
                print(f"Triggering main webhook...")
                result_text = f"Main webhook triggered!"
                return [{"id": "wh_result_main", "text": result_text }]
            else:
                 return [{"id": "error", "text": "Unexpected state for webhook."}]
        elif first_step == "secure_note":
            # User entered text (password), which is current_step_data
            encrypted_password = current_step_data
            password = decrypt_text(encrypted_password)
            if password == "correct_password": # Replace with real check
                note_content = "This is the secret note content."
                encrypted_note = encrypt_text(note_content) # Encrypt the result
                if encrypted_note:
                     return [{ "id": "note_content", "text": encrypted_note, "encrypted": True }]
                else:
                    return [{"id": "enc_error", "text": "Error encrypting note."}]
            else:
                return [{"id": "pw_incorrect", "text": "Password incorrect."}]
        elif first_step == "thermostat":
            # User selected an integer, which is current_step_data as a string
            temp_str = current_step_data
            try:
                temperature = int(temp_str)
                print(f"Setting thermostat to {temperature}°C")
                result_text = f"Thermostat set to {temperature}°C."
                return [{"id": "thermo_result", "text": result_text}]
            except ValueError:
                print(f"Invalid integer string received: {temp_str}")
                return [{"id": "thermo_error", "text": "Invalid temperature value received."}]
        elif first_step == "check_in":
            # User confirmed location, which is current_step_data as "lat,lon" string
            location_str = current_step_data
            try:
                latitude, longitude = map(float, location_str.split(','))
                print(f"User checked in at Latitude: {latitude}, Longitude: {longitude}")
                result_text = f"Checked in at {latitude:.4f}, {longitude:.4f}."
                return [{"id": "checkin_result", "text": result_text}]
            except (ValueError, IndexError):
                print(f"Invalid location string received: {location_str}")
                return [{"id": "checkin_error", "text": "Invalid location format received."}]
        elif first_step == "select_features":
            # User made selections in multi-choice. current_step_data is "id1&id2&..."
            # Note: The app navigated here based on the *first* item originally sent
            # in get_feature_options(), which was "feature_a". So state[0] is "select_features",
            # and the *backend* needs to remember that state[1] should contain the multi-choice result.
            selected_ids_str = current_step_data
            selected_ids = selected_ids_str.split('&') if selected_ids_str else []
            print(f"Selected features: {selected_ids}")
            # Perform action based on selected features
            result_text = f"Enabled features: {', '.join(selected_ids) if selected_ids else 'None'}"
            return [{"id": "features_result", "text": result_text}]

    # Example: Handling the light toggle (final step in lights flow)
    elif len(state) == 3 and first_step == "lights":
        room = state[1]
        light_action = current_step_data # e.g., "living_room_main_toggle"
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

def get_feature_options():
    """Returns the options for the multi-choice prompt."""
    # IMPORTANT: The first item's 'nextPrompt' determines what happens AFTER selection.
    # It should usually be nil or lead to a result view.
    # Here, we'll just display the result immediately.
    return [
        {"id": "feature_a", "text": "Feature A", "icon": "a.circle"}, # This item defines the next step
        {"id": "feature_b", "text": "Feature B", "icon": "b.circle"},
        {"id": "feature_c", "text": "Feature C (Encrypted)", "icon": "c.circle", "encrypted": True, "text": encrypt_text("Feature C")},
        {"id": "feature_d", "text": "Feature D", "icon": "d.circle"}
    ]

if __name__ == '__main__':
    # Use 0.0.0.0 to make it accessible on your network
    # Ensure firewall allows access on port 5001
    # Use HTTPS in production! (e.g., behind a reverse proxy like Nginx)
    app.run(host='0.0.0.0', port=5001, debug=True)
