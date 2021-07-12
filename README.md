# Check TLS Suites

Provides list of TLS suite names and recommendation status per IANA given either:

- A hex stream of cipher suites like one might extract in Wireshark from a TLS Client Hello, or
- A comma-separated list of integers representing cipher suites as one might extract with `tshark -r some-special.pcap -Y 'tls.handshake.ciphersuites' -T fields -e 'tls.handshake.ciphersuite'`

## Options
```
check-tls-suites -h
Check TLS Suites 0.1.1
Anthony J. Martinez <anthony@ajmartinez.com>
Displays TLS cipher suite names and recommendation status from IANA for a set of given ciphers

USAGE:
    check-tls-suites [FLAGS] -f <from_file> -w --hex-stream <hex_stream> --int-list <int_list>

FLAGS:
    -w               Download the IANA TLS parameters CSV from https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -f <from_file>                   Path to the IANA TLS parameters CSV
        --hex-stream <hex_stream>    Provide the hex stream of cipher specs (from Wireshark for example)
        --int-list <int_list>        Provide a comma-separated list of cipher spec integer representations (from tshark
                                     for example
```

## Example - IANA CSV on Disk. Hex Stream from Wireshark Client Hello. Legacy IOT Device
```
check-tls-suites -f /home/user/Downloads/tls-parameters-4.csv --hex-stream c024c028003dc026c02a006b006ac00ac0140035c005c00f00390038c023c027003cc025c02900670040c009c013002fc004c00e00330032c02cc02bc030009dc02ec032009f00a3c02f009cc02dc031009e00a2c008c012000ac003c00d0016001300ff
!Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xC024)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xC028)' is NOT recommended for use!
!Cipher suite 'TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003D)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 (0xC026)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 (0xC02A)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006B)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 (0x006A)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xC00A)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xC014)' is NOT recommended for use!
!Cipher suite 'TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (0xC005)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (0xC00F)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA (0x0038)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xC023)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027)' is NOT recommended for use!
!Cipher suite 'TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 (0xC025)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (0xC029)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 (0x0040)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xC009)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013)' is NOT recommended for use!
!Cipher suite 'TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (0xC004)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (0xC00E)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA (0x0032)' is NOT recommended for use!
Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, (0xC02C)' is recommended for use.
Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, (0xC02B)' is recommended for use.
Cipher suite 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, (0xC030)' is recommended for use.
!Cipher suite 'TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009D)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02E)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 (0xC032)' is NOT recommended for use!
Cipher suite 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, (0x009F)' is recommended for use.
!Cipher suite 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 (0x00A3)' is NOT recommended for use!
Cipher suite 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, (0xC02F)' is recommended for use.
!Cipher suite 'TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02D)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (0xC031)' is NOT recommended for use!
Cipher suite 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, (0x009E)' is recommended for use.
!Cipher suite 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 (0x00A2)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xC008)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xC012)' is NOT recommended for use!
!Cipher suite 'TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000A)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (0xC003)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (0xC00D)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA (0x0013)' is NOT recommended for use!
!Cipher suite 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF)' is NOT recommended for use!
```

## Example - IANA CSV from the web. Integer list from tshark. Legacy IOT Device
```
check-tls-suites -w --int-list 49188,49192,61,49190,49194,107,106,49162,49172,53,49157,49167,57,56,49187,49191,60,49189,49193,103,64,49161,49171,47,49156,49166,51,50,49196,49195,49200,157,49198,49202,159,163,49199,156,49197,49201,158,162,49160,49170,10,49155,49165,22,19,255
!Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xC024)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xC028)' is NOT recommended for use!
!Cipher suite 'TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003D)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 (0xC026)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 (0xC02A)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006B)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 (0x006A)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xC00A)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xC014)' is NOT recommended for use!
!Cipher suite 'TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (0xC005)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (0xC00F)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA (0x0038)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xC023)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027)' is NOT recommended for use!
!Cipher suite 'TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 (0xC025)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (0xC029)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 (0x0040)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xC009)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013)' is NOT recommended for use!
!Cipher suite 'TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (0xC004)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (0xC00E)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA (0x0032)' is NOT recommended for use!
Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, (0xC02C)' is recommended for use.
Cipher suite 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, (0xC02B)' is recommended for use.
Cipher suite 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, (0xC030)' is recommended for use.
!Cipher suite 'TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009D)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02E)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 (0xC032)' is NOT recommended for use!
Cipher suite 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, (0x009F)' is recommended for use.
!Cipher suite 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 (0x00A3)' is NOT recommended for use!
Cipher suite 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, (0xC02F)' is recommended for use.
!Cipher suite 'TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02D)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (0xC031)' is NOT recommended for use!
Cipher suite 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, (0x009E)' is recommended for use.
!Cipher suite 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 (0x00A2)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xC008)' is NOT recommended for use!
!Cipher suite 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xC012)' is NOT recommended for use!
!Cipher suite 'TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000A)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (0xC003)' is NOT recommended for use!
!Cipher suite 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (0xC00D)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016)' is NOT recommended for use!
!Cipher suite 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA (0x0013)' is NOT recommended for use!
!Cipher suite 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF)' is NOT recommended for use!
```

### License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
