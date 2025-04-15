# Scrapyard Sharjah

A powerful website that was used for the Scrapyard SHJ Hackathon 2025.
Includes the Bank, Admin Panel, Website, Shop, Mission Board, Bounty, Leaderboard, and many API's

Includes a Hunt The Flag (HTF) platform designed for cybersecurity enthusiasts to 
solve challenges across various domains such as cryptography, web exploitation, 
reverse engineering, forensics, and steganography.

## Features

- User authentication and session management.
- Multiple challenges with automated flag validation.
- Admin panel for managing challenges and submissions.
- API endpoints for database queries and other administrative tasks.
- Rate-limiting and error handling for secure operations.
- Fully fledged system for the Bank, Admin Panel, Website, Shop, Mission Board, Bounty, Leaderboard, and many API's.

### Challenges

1. **Cryptography**: Decrypt a ROT13-encrypted message to uncover the flag.
2. **Web Exploitation**: Bypass the login page using SQL Injection to discover the flag.
3. **Reverse Engineering**: Analyze a binary file to find a hardcoded key.
4. **Forensics**: Analyze a PCAP file in Wireshark to find a hidden key.
5. **Steganography**: Extract hidden data from an image file using an automated script.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/DefinetlyNotAI/Scrapyard_Bounty.git
    cd ctf-platform
    ```

2. Create a virtual environment and activate it:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

4. Modify the scripts environment variables to your secrets

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License.
See the [LICENSE](LICENSE) file for details.

---
