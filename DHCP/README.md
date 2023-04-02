# Client:
The overall process of running the client is as follows:
The client is executed and sends a Discovery message, then waits for an Offer message from the server. After receiving the Offer, it sends a Request message and waits for an Ack. After receiving the Ack, the client should print the received IP address in the terminal.

## Implementation Details:

* The DHCPDiscover and DHCPRequest requests are implemented in the client.
* If Ack is not received within a specified time interval (timeout), the client must restart the process by sending a DISCOVER message again. The timeout value can be set arbitrarily in the code.
* The DISCOVER message itself has a timer that checks if a certain amount of time has passed since the last DISCOVER message was sent. If the IP address has not been obtained, or if it has been obtained but has expired, the DISCOVER message is sent again. The waiting time for this timer is calculated as follows: (details provided in the Persian text)
* In the client side, two variables with the names cutoff-backoff and interval-initial are kept with default values of 120 and 10 seconds respectively.
* After sending the first DISCOVER message, this timer starts and waits for the interval-initial duration. After this period, if necessary, DISCOVER will be sent again.
* After sending the second DISCOVER, it does not wait for the interval-initial duration, but this interval is calculated by the R2P formula, where R is a random number between 0 and 1, and P is the Previous interval. This increase in interval lasts until it reaches cutoff-backoff, and if it exceeds that, it will be set to that value.

# Server:
The server is always ready to receive a DHCP Discovery, and when it receives one, it sends an Offer and then waits to receive a Request. After receiving a Request, it sends an Ack message. The following implementation details should be considered:

## Implementation Details:

* The server has DHCPOffer and DHCPAck.
* The server is multi-threaded, so after receiving Discovery, it continues with all the subsequent stages separately for each client and is continuously ready to receive Discovery messages.
* The server has an IP Pool from which it assigns IP to clients. Repeating an IP should not be assigned to another client, and a duplicate IP should not be assigned. The server must consider the Lease time for each client, and after the Lease time ends, it should return the IP to the Pool, and that IP should be among the available IPs.
* If an IP was previously assigned to a MAC address and a request for IP comes again from the same MAC address, the server should not assign a new IP to it, and the old IP, whose lease time has not expired, is sent again, and its lease time is renewed.
* The server is able to reserve IP for specific MAC addresses, i.e., consider static IP for special devices. When an IP is reserved for a device, it cannot be assigned to any other client even if the client for which the IP is reserved is offline at that moment.
* The server also has the ability to block specific MAC addresses, so if a request for IP comes from specific MAC addresses, no response is given.
* The server is able to keep the name of the device, the remaining time until the IP expires, the assigned IP itself, and the assigned MAC address for each assigned IP. This information can be viewed using the "clients_show" command in the console.
