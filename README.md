
# Kindly Evasive

**Kindly Evasive** is a post-exploitation and Initial Access Payload (IAP) toolkit designed for building and injecting payloads directly into memory. With its robust features, Kindly Evasive allows users to efficiently manage payloads, facilitating seamless operations during engagements.

## Features

### Builder
- **Payload Creation:** Build and inject configurations into a PE section that executes upon payload execution.
- **Payload Source:** Load unencrypted payloads from your local computer or a remote server.
- **Payload Encryption:** Encrypt payloads using various encryption methods.
- **Chunking:** Optionally separate the payload into multiple files (chunks) for enhanced flexibility.

### Payload Options
- **Shellcode Injection:** Support for injecting shellcode to maintain stealth and efficiency.
- **In-Memory PE Loader:** Features a PE loader capable of supporting Cobalt Strike beacons.

## Options

```plaintext
--help                       Display this help message.
--output-dir                 Full file path including file name to output payload to.
--verbose                    Print verbose output.
--debug                      Enables breakpoints and console output on the payload file.
```

### Encryption Options
```plaintext
--encryption-method          Specify encryption method (XOR, AES, RC4).
--encryption-key             Set the encryption key to be used.
```

### Payload Input Options
```plaintext
--local-file                 Load unencrypted payload file from local computer. Argument is the full file path to the payload file.
--remote-file                Fetch unencrypted payload file from remote server. Argument is the full URL to the server hosting the payload file.
```

### Payload Features
```plaintext
--payload-type               Specify type of payload (raw, dll, beacon).
--dummy-fetch                Make HTTP requests to dummy APIs alongside payload requests.
```

### Payload Delivery Options
```plaintext
--staging-server             URL of web server used to host initial access payloads after build is complete.
--payload-size               Size of payload in bytes.
--chunk-count                Split encrypted payload into multiple files. Example: --chunk 3 (will output 3 .bin files).
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/rottaj/KindlyEvasive.git
   cd kindly-evasive
   ```

2. Install required dependencies (if any).

3. Build the toolkit:
   ```bash
   make build
   ```

## Usage

To get started with Kindly Evasive, run the following command:

```bash
./KindlyBuilder -h
```

This command will provide you with all available options and configurations to tailor your payloads as needed.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any features or improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

For any questions or support, feel free to open an issue in the repository or reach out to the maintainers. Happy testing!
