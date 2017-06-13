## How to get Apple Pay private key

### 1. Export your private key as .p12

Open your Keychain Access, locate your Apple Pay private key, export it as .p12 file.

### 2. Convert .p12 to .pem
    $ openssl pkcs12 -in YourPrivateKey.p12 -nodes -out YourPrivateKey.pem

### 3. Print private key
    $ cat YourPrivateKey.pem

### 4. You got the private key

The base64 encoded string between `BEGIN` and `END` is your private key.

    -----BEGIN EC PRIVATE KEY-----
    {Your-Private-Key-Is-Here}
    -----END EC PRIVATE KEY-----

Then you are able to use it like below

    var p = new ApplePayParameters
    {
        PrivateKey = "{Your-Private-Key-Is-Here}"
    };

## License

Licensed under the [MIT](LICENSE) License.
