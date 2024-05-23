#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "nvs_flash.h"
#include "esp_partition.h"

#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"
#include "esp_gatt_defs.h"
#include "esp_bt_main.h"
#include "esp_bt_defs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/uart.h"
#include "driver/gpio.h"
#include "sdkconfig.h"

#include "uECC.h"

#define CHECK_BIT(var, pos) ((var) & (1 << (7 - pos)))

#define TEST_RTS (18)
#define TEST_CTS (18)

#define UART_PORT_NUM (0)
#define UART_BAUD_RATE (115200)
#define TASK_STACK_SIZE (2048)

#define BUF_SIZE (1024)

// Set custom modem id before flashing:
//static const uint32_t modem_id = 0x1A2B3C4D;
static const uint32_t modem_id = 0x00000001;

static const char *LOG_TAG = "findmy_modem";

/** Callback function for BT events */
static void esp_gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param);

/** Random device address */
static esp_bd_addr_t rnd_addr = {0xFF, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

/** Advertisement payload */
static uint8_t adv_data[31] = {
    0x1e,       /* Length (30) */
    0xff,       /* Manufacturer Specific Data (type 0xff) */
    0x4c, 0x00, /* Company ID (Apple) */
    0x12, 0x19, /* Offline Finding type and length */
    0x00,       /* State */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, /* First two bits */
    0x00, /* Hint (0x00) */
};

uint32_t swap_uint32(uint32_t val)
{
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | (val >> 16);
};

/* https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/bluetooth/esp_gap_ble.html#_CPPv420esp_ble_adv_params_t */
static esp_ble_adv_params_t ble_adv_params = {
    // Advertising min interval:
    // Minimum advertising interval for undirected and low duty cycle
    // directed advertising. Range: 0x0020 to 0x4000 Default: N = 0x0800
    // (1.28 second) Time = N * 0.625 msec Time Range: 20 ms to 10.24 sec
    .adv_int_min = 0x0640,
    // Advertising max interval:
    // Maximum advertising interval for undirected and low duty cycle
    // directed advertising. Range: 0x0020 to 0x4000 Default: N = 0x0800
    // (1.28 second) Time = N * 0.625 msec Time Range: 20 ms to 10.24 sec
    .adv_int_max = 0x0C80,
    // Advertisement type
    .adv_type = ADV_TYPE_NONCONN_IND,
    // Use the random address
    .own_addr_type = BLE_ADDR_TYPE_RANDOM,
    // All channels
    .channel_map = ADV_CHNL_ALL,
    // Allow both scan and connection requests from anyone.
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

// Function to handle Bluetooth Low Energy (BLE) GAP (Generic Access Profile) events.
static void esp_gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    // Variable to hold error status.
    esp_err_t err;

    // Switch statement to handle different types of GAP events.
    switch (event)
    {
    // Event for when setting of raw advertising data is complete.
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
        // Start advertising with the specified parameters.
        esp_ble_gap_start_advertising(&ble_adv_params);
        break;

    // Event for when advertising start operation is complete.
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
        // Check if advertising started successfully.
        if ((err = param->adv_start_cmpl.status) != ESP_BT_STATUS_SUCCESS)
        {
            // Log an error message if advertising start failed.
            ESP_LOGE(LOG_TAG, "advertising start failed: %s", esp_err_to_name(err));
        }
        else
        {
            // Log a debug message if advertising started successfully.
            ESP_LOGD(LOG_TAG, "advertising started");
        }
        break;

    // Event for when advertising stop operation is complete.
    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
        // Check if advertising stopped successfully.
        if ((err = param->adv_stop_cmpl.status) != ESP_BT_STATUS_SUCCESS)
        {
            // Log an error message if advertising stop failed.
            ESP_LOGE(LOG_TAG, "adv stop failed: %s", esp_err_to_name(err));
        }
        else
        {
            // Log a debug message if advertising stopped successfully.
            ESP_LOGD(LOG_TAG, "advertising stopped");
        }
        break;

    // Default case to handle any other unspecified events.
    default:
        break;
    }
}

// Function to validate a compressed public key.
int is_valid_pubkey(uint8_t *pub_key_compressed)
{
    // Array to hold the public key with a prefix byte for the decompression.
    uint8_t with_sign_byte[29];

    // Array to hold the uncompressed public key.
    uint8_t pub_key_uncompressed[128];

    // Get the ECC curve parameters for secp224r1.
    const struct uECC_Curve_t *curve = uECC_secp224r1();

    // Set the first byte to 0x02 to indicate a compressed key with even y-coordinate.
    with_sign_byte[0] = 0x02;

    // Copy the compressed public key into 'with_sign_byte', starting from the second byte.
    memcpy(&with_sign_byte[1], pub_key_compressed, 28);
    
    // // Print each byte in hexadecimal format
    // for (int i = 0; i < 29; i++) {
    //     printf("%02x ", with_sign_byte[i]);
    // }
    // printf("\n");

    // Decompress the public key.
    uECC_decompress(with_sign_byte, pub_key_uncompressed, curve);

    // Check if the decompressed public key is valid.
    if (!uECC_valid_public_key(pub_key_uncompressed, curve))
    {
        // Log a warning if the public key is invalid.
        //printf("Generated public key tested as invalid");

        // Return 0 to indicate an invalid public key.
        return 0;
    }

    // Return 1 to indicate a valid public key.
    return 1;
}

// Function to compute a compressed public key from a given private key.
void pub_from_priv(uint8_t *pub_compressed, uint8_t *priv)
{
    // Get the ECC curve parameters for secp224r1.
    const struct uECC_Curve_t *curve = uECC_secp224r1();

    // Array to hold the temporary uncompressed public key.
    uint8_t pub_key_tmp[128];

    // Compute the uncompressed public key from the private key using the specified ECC curve.
    uECC_compute_public_key(priv, pub_key_tmp, curve);

    // Compress the public key and store it in the provided output buffer.
    uECC_compress(pub_key_tmp, pub_compressed, curve);
}

// Function to set a Bluetooth device address (addr) based on a given public key.
void set_addr_from_key(esp_bd_addr_t addr, uint8_t *public_key)
{
    // Set the first byte of the address.
    // OR operation with 0b11000000 ensures the two most significant bits are set to 1,
    // which is typical for Bluetooth addresses derived from public keys.
    addr[0] = public_key[0] | 0b11000000;

    // Copy the next 5 bytes of the public key to the Bluetooth address.
    // This creates a unique address based on the public key.
    addr[1] = public_key[1];
    addr[2] = public_key[2];
    addr[3] = public_key[3];
    addr[4] = public_key[4];
    addr[5] = public_key[5];
}

void set_payload_from_key(uint8_t *payload, uint8_t *public_key)
{
    /* copy last 22 bytes */
    memcpy(&payload[7], &public_key[6], 22);
    /* append two bits of public key */
    payload[29] = public_key[0] >> 6;
}

// Function to copy a 4-byte (32-bit) value from 'src' to 'dst', converting it to big-endian format.
void copy_4b_big_endian(uint8_t *dst, const uint32_t *src)
{
    // Cast the 32-bit source integer to a byte array for byte-wise access.
    const uint8_t *byteArray = (const uint8_t *)src;

    // Copy bytes from the source to the destination in reverse order
    // to convert from little-endian (typical in x86 architecture) to big-endian format.
    // In big-endian, the most significant byte is at the smallest memory address.
    dst[0] = byteArray[3]; // Most significant byte
    dst[1] = byteArray[2];
    dst[2] = byteArray[1];
    dst[3] = byteArray[0]; // Least significant byte
}

// index as first part of payload to have an often changing MAC address
// [2b magic] [4byte index] [4byte msg_id] [4byte modem_id] [000.000] [1bit]
// There is a rade-off between sending and receiving throughput (e.g. we could also use a 1-byte lookup table)
// Function to set a Bluetooth address and payload based on a constructed public key.
void set_addr_and_payload_for_bit(uint32_t index, uint32_t msg_id, uint8_t bit)
{
    // Counter for valid public keys found.
    uint32_t valid_key_counter = 0;

    // Array to hold the public key, initialized to zero.
    static uint8_t public_key[28] = {0};

    // Set the first two bytes to a magic value, possibly for identification or protocol purposes.
    public_key[0] = 0xBA; // Magic value
    public_key[1] = 0xBE;

    // Copy the 'index', 'msg_id', and 'modem_id' into the public key in big-endian format.
    copy_4b_big_endian(&public_key[2], &index);
    copy_4b_big_endian(&public_key[6], &msg_id);
    copy_4b_big_endian(&public_key[10], &modem_id);

    // Set the last byte of the public key to the 'bit' parameter.
    public_key[27] = bit;

    // // Print the public key in hexadecimal format
    // for (int i = 0; i < sizeof(public_key); i++) {
    //     printf("%02X ", public_key[i]); // Print each byte as a two-digit hexadecimal number
    // }
    // printf("\n"); // Add a newline at the end

    // Loop to find a valid public key.
    do
    {
        // Update part of the public key with the current counter value.
        copy_4b_big_endian(&public_key[14], &valid_key_counter);

        // Increment the valid key counter for the next iteration.
        valid_key_counter++;
    } while (!is_valid_pubkey(public_key)); // Continue until a valid public key is found.

    // Log the public key and the number of attempts to find a valid one.

    //ESP_LOGI(LOG_TAG, "  pub key to use (%lu. try): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x ... %02x", valid_key_counter, public_key[0], public_key[1], public_key[2], public_key[3], public_key[4], public_key[5], public_key[6], public_key[7], public_key[8], public_key[9], public_key[10], public_key[11], public_key[12], public_key[13], public_key[14], public_key[15], public_key[16], public_key[17], public_key[19], public_key[19], public_key[20], public_key[21], public_key[22], public_key[23], public_key[24], public_key[25], public_key[26], public_key[27]);

    // Set the Bluetooth address based on the constructed public key.
    set_addr_from_key(rnd_addr, public_key);

    // Set the payload based on the constructed public key.
    set_payload_from_key(adv_data, public_key);
}

// void log_sha256_hash(uint8_t *public_key, size_t pub_key_length)
// {
//     unsigned char hash[SHA256_DIGEST_LENGTH];

//     // Compute the SHA256 hash of the public key
//     SHA256(public_key, pub_key_length, hash);

//     // Print the hash in hexadecimal format
//     printf("SHA256 Hash: ");
//     for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
//     {
//         printf("%02x", hash[i]);
//     }
//     printf("\n");
// }

// No error handling yet
// Function to reset the BLE advertising with a new random address and advertising data.
void reset_advertising()
{
    // Variable to hold the status of BLE operations.
    esp_err_t status;

    // Stop any ongoing BLE advertising.
    esp_ble_gap_stop_advertising();

    // Set a new random address for BLE advertising.
    // If setting the random address fails, log an error and return from the function.
    if ((status = esp_ble_gap_set_rand_addr(rnd_addr)) != ESP_OK)
    {
        ESP_LOGE(LOG_TAG, "couldn't set random address: %s", esp_err_to_name(status));
        return;
    }

    // Configure the BLE advertising with new data.
    // If configuration fails, log an error and return from the function.
    if ((esp_ble_gap_config_adv_data_raw((uint8_t *)&adv_data, sizeof(adv_data))) != ESP_OK)
    {
        ESP_LOGE(LOG_TAG, "couldn't configure BLE adv: %s", esp_err_to_name(status));
        return;
    }
}

// Function to send data over BLE by encoding it into BLE advertising packets.
void send_data_once_blocking(uint8_t *data_to_send, uint32_t len, uint32_t msg_id)
{
    // Print the data to send along with its message ID.
    printf("Data to send (msg_id: %lu): %s\n", msg_id, data_to_send);

    // Variable to hold the current bit value (0 or 1).
    uint8_t current_bit = 0;

    // Iterate over each byte of the data to send.
    for (int by_i = 0; by_i < len; by_i++)
    {
        // Print information about the byte being sent.
        printf("  Sending byte %d/%lu (0x%02x)\n", by_i, len - 1, data_to_send[by_i]);

        // Iterate over each bit of the current byte.
        for (int bi_i = 0; bi_i < 8; bi_i++)
        {
            // Check if the current bit is set (1) or not (0).
            current_bit = CHECK_BIT(data_to_send[by_i], bi_i) ? 1 : 0;

            // Print information about the bit being sent.
            printf("  Sending byte %d, bit %d: %d\n", by_i, bi_i, current_bit);

            // Set the BLE address and payload based on the current bit.
            set_addr_and_payload_for_bit(by_i * 8 + bi_i, msg_id, current_bit);

            // Print the new device address.
            printf("    resetting. Will now use device address: %02x %02x %02x %02x %02x %02x\n", rnd_addr[0], rnd_addr[1], rnd_addr[2], rnd_addr[3], rnd_addr[4], rnd_addr[5]);

            // Reset the BLE advertising with the new address and payload.
            reset_advertising();

            // Delay for a short time before sending the next bit.
            vTaskDelay(2);
        }
    }

    // Stop BLE advertising after sending all data.
    esp_ble_gap_stop_advertising();
}

// Function to read a line from a UART port or dismiss the input if incomplete.
uint8_t *read_line_or_dismiss(int *len)
{
    // Allocate memory for the line buffer.
    uint8_t *line = (uint8_t *)malloc(BUF_SIZE);

    // Variable to hold the number of bytes read.
    int size;

    // Pointer for tracking the position in the line buffer.
    uint8_t *ptr = line;

    // Infinite loop to read bytes one by one.
    while (1)
    {
        // Read a single byte from the UART port with a timeout of 20ms.
        size = uart_read_bytes(UART_PORT_NUM, (unsigned char *)ptr, 1, 20 / portTICK_RATE_MS);

        // Check if one byte was successfully read.
        if (size == 1)
        {
            // If the byte is a newline character, terminate the line and return.
            if (*ptr == '\n')
            {
                *ptr = 0;          // Replace newline with null terminator.
                *len = ptr - line; // Calculate the length of the line.
                return line;       // Return the read line.
            }
            // Move the pointer to the next position in the buffer.
            ptr++;
        }
        else
        {
            // If no byte is read or an error occurs, free the buffer and dismiss the line.
            free(line);
            ESP_LOGI(LOG_TAG, "Dismissing line");
            return 0;
        }
    }
}

void init_serial()
{
    uart_config_t uart_config = {
        .baud_rate = UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_APB,
    };
    int intr_alloc_flags = 0;

    ESP_ERROR_CHECK(uart_driver_install(UART_PORT_NUM, BUF_SIZE * 2, 0, 0, NULL, intr_alloc_flags));
    ESP_ERROR_CHECK(uart_param_config(UART_PORT_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART_PORT_NUM, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, TEST_RTS, TEST_CTS));
}

// Main application entry point.
void app_main(void)
{
    // Initialize non-volatile storage.
    ESP_ERROR_CHECK(nvs_flash_init());

    // Release memory dedicated to classic Bluetooth as only BLE will be used.
    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    // Configuration for the Bluetooth controller.
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();

    // Initialize the Bluetooth controller with the specified configuration.
    esp_bt_controller_init(&bt_cfg);

    // Enable Bluetooth in BLE mode.
    esp_bt_controller_enable(ESP_BT_MODE_BLE);

    // Initialize and enable the Bluetooth stack.
    esp_bluedroid_init();
    esp_bluedroid_enable();

    // Define initial test message to send after boot.
    static uint8_t data_to_send[] = "Hello World.";

    // Variable to store the status of BLE operations.
    esp_err_t status;

    // Register the GAP callback function.
    if ((status = esp_ble_gap_register_callback(esp_gap_cb)) != ESP_OK)
    {
        // Log an error and return if GAP registration fails.
        ESP_LOGE(LOG_TAG, "gap register error: %s", esp_err_to_name(status));
        return;
    }

    // Variable to keep track of message IDs.
    uint32_t current_message_id = 0;

    // Log the initial message being sent.
    ESP_LOGI(LOG_TAG, "Sending initial default message: %s", data_to_send);

    // Send the initial test message.
    send_data_once_blocking(data_to_send, sizeof(data_to_send), current_message_id);

    // Log the switch to serial modem mode.
    ESP_LOGI(LOG_TAG, "Entering serial modem mode");
    // Initialize serial communication.
    init_serial();

    // Send a message over UART indicating that the serial mode is activated.
    uart_write_bytes(UART_PORT_NUM, (const char *)"Serial activated. Waiting for text lines.\n", 42);

    // Initialize variables for handling new data.
    int len = sizeof(data_to_send);
    uint8_t *data = data_to_send; // Pointer to the current data to send.
    uint8_t *new_data = 0;

    // Main loop.
    while (1)
    {
        // Read new data from UART, if available.
        if ((new_data = read_line_or_dismiss(&len)))
        {
            // Update the data pointer and increment message ID if new data is received.
            data = new_data;
            current_message_id++;
            ESP_LOGI(LOG_TAG, "Received line (len: %d): %s", len, data);
        }
        else
        {
            // Log that there's no new input and the old data will be sent.
            ESP_LOGI(LOG_TAG, "No new input. Continuing sending old data");
        }

        // Send data over BLE if it's available.
        if (data)
        {
            send_data_once_blocking(data, len, current_message_id);
        }

        // Delay to allow other tasks to run.
        vTaskDelay(200);
    }

    // Stop BLE advertising when exiting the loop.
    esp_ble_gap_stop_advertising();
}
