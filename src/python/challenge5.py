# Append the flag to the image data
import os
import shutil

from faker import Faker

# NOTICE
# The line in app.py is hardcoded as I couldn't find a way to dynamically get the correct line
# Rerunning this script will generate a new flag location, and so you must find the correct line again

fake = Faker()

# embed_flag_in_image.py
flag = "KEY{i_tES_TYU564678IUY^&*(I_E%$rf}"
input_image_path = "../assets/scrapyard.jpeg"

# Read the original image file
with open(input_image_path, "rb") as image_file:
    image_data = image_file.read()

# Generate fake text
image_data_with_flag = image_data + fake.text(max_nb_chars=10000).encode() + flag.encode() + fake.text(
    max_nb_chars=10000).encode()

import random

if os.path.exists("../assets/images"):
    shutil.rmtree("../assets/images")
os.makedirs("../assets/images")

# Generate fake text and embed the flag in one of the files
for i in range(100):
    image_data_with_flag = image_data + fake.text(max_nb_chars=10000).encode()
    if i == random.randint(0, 99):  # Randomly choose one file to contain the flag
        print(f"Flag is in file C5_{i}.jpeg")
        image_data_with_flag += flag.encode()
    image_data_with_flag += fake.text(max_nb_chars=10000).encode()

    # Save the modified image data to a new file
    output_image_path = f"assets/images/C5_{i}.jpeg"
    with open(output_image_path, "wb") as output_file:
        output_file.write(image_data_with_flag)
