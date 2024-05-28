#  Intrusion Detection aned Prevention System using Scapy

##  Simple anomaly and behaviour based detection
###  Protection from SYN Flood Attacks
- **SYN Cookie Mechanism**: Utilizes SYN cookies to handle half-open connections and prevent server resource exhaustion.


### Protection from Excessive IP Traffic
- **Rate-Based Filters**: Applies filters that limit the rate of incoming packets from a single IP address.


### Protection from Port Scanning
- **Dynamic Response**: Automatically blocks IP addresses that exhibit port scanning behavior for a defined period.

### Protection from Excessive HTTP Attacks
- **HTTP Rate Limiting**: Limits the number of HTTP requests from a single IP within a specified timeframe.

### Blacklisting System for Simple Prevention Measures
- **Automated Blacklisting**: Automatically adds IP addresses that trigger multiple detection rules to a blacklist.

*Note: These rules can be customized and added as required to enhance the protection mechanisms of the IDPS.*
