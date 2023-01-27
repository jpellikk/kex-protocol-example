# Key Exchange Protocol Example

This project creates two executables (initiator and responder) that run a key exchange protocol over an UDP localhost connection.

To compile the initiator and responder executables you must install the following packages (OpenSSL must be version 3):
```sh
$ sudo apt-get install build-essential pkg-config openssl -y
```

Generate an elliptic curve public/private key pair for the responder:
```sh
$ openssl ecparam -name prime256v1 -genkey -noout -out key.pem
$ openssl ec -in key.pem -noout -text  ### print the key pair
```

Start the responder executable:
```sh
$ ./responder 5001 key.pem
```

Run the initiator executable:
```sh
$ ./initiator localhost 5001 prime256v1
```
