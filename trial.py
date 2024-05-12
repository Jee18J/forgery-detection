import cv2
import os
import hashlib
from hashlib import sha3_256
import exifread

# Function to calculate SHA-3 hash of an image's bytes
def calculate_sha3(image):
    hash_sha3 = sha3_256()
    block_size = 1024  # Define block size for processing image data

    # Absorb phase: process image data
    for block_start in range(0, len(image), block_size):
        block_end = min(block_start + block_size, len(image))
        block = image[block_start:block_end]
        hash_sha3.update(block)

    # Squeeze phase: return final hash
    return hash_sha3.hexdigest()

# Function to detect forgery using SHA-3 and metadata analysis
def detect_forgery(original_image_path, test_image_path):
    if not os.path.exists(original_image_path) or not os.path.exists(test_image_path):
        return "Error: One or both image paths do not exist."

    original_image = cv2.imread(original_image_path)
    test_image = cv2.imread(test_image_path)

    if original_image is None or test_image is None:
        return "Error: Failed to load one or both images. Check file paths and file integrity."

    original_sha3 = calculate_sha3(original_image.tobytes())
    test_sha3 = calculate_sha3(test_image.tobytes())

    if original_sha3 == test_sha3:
        return f"No forgery detected.\nOriginal image SHA-3 hash: {original_sha3}\nTest image SHA-3 hash: {test_sha3}"
    
    if original_image.shape != test_image.shape:
        return f"Forgery detected: Dimensional change.\nOriginal SHA-3 hash: {original_sha3}\nTest SHA-3 hash: {test_sha3}"

    # Check for pixel differences
    diff = cv2.absdiff(original_image, test_image)
    if cv2.countNonZero(cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)) > 0:
        return f"Forgery detected: Image content modification.\nOriginal SHA-3 hash: {original_sha3}\nTest SHA-3 hash: {test_sha3}"

    return "Forgery detected: Unidentified modification."

# Function to extract metadata from an image
def get_image_metadata(image_path):
    with open(image_path, 'rb') as f:
        tags = exifread.process_file(f)
        metadata = {tag: str(tags[tag]) for tag in tags}
    return metadata

# Function to hide data within an image (basic LSB steganography)
def hide_data(image, data):
    if image is None:
        return None, "Error: No image provided."

    data_bytes = bytes(data, 'utf-8')
    height, width, _ = image.shape
    max_bytes = height * width * 3 // 8

    if len(data_bytes) > max_bytes:
        return None, "Error: Insufficient capacity to hide data."

    index = 0
    for byte in data_bytes:
        for bit in range(8):
            val = (byte >> bit) & 1
            i, j, k = (index // 3) % width, index // (3 * width), index % 3
            image[j, i, k] = (image[j, i, k] & ~1) | val
            index += 1

    return image, None

# Function to extract data from an image
def extract_data(image):
    height, width, _ = image.shape
    bit_list = []

    for j in range(height):
        for i in range(width):
            for k in range(3):
                bit_list.append(image[j, i, k] & 1)

    byte_list = []
    for byte_index in range(0, len(bit_list) - 7, 8):
        byte = 0
        for bit_index in range(8):
            byte |= (bit_list[byte_index + bit_index] << bit_index)
        byte_list.append(byte)

    data_bytes = bytes(byte_list)
    return data_bytes.decode(errors='ignore')

# Example usage:
original_image_path = "original_image.jpg"
test_image_path = "forged_image.jpg"
hidden_data = "This is a secret message."

original_image = cv2.imread(original_image_path)
if original_image is None:
    print("Error: Failed to load original image.")
else:
    stego_image, error = hide_data(original_image, hidden_data)
    if stego_image is None:
        print(error)
    else:
        cv2.imwrite("stego_image.png", stego_image)
        result = detect_forgery(original_image_path, "stego_image.png")
        print(result)
