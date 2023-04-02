# First Part: Sending Requests
You can create a socket using Python by searching the internet and specifying the DNS port and address to send your desired message. To ensure that your message is sent to the specified port, you can create a server socket in another program and send messages to it for testing purposes.

# Second Part: Sending DNS Queries to the Server

Receive an address name from the user as input and create the message to retrieve the A record for that address name based on the responses in section 1. As an optional part, multiple address names can be provided to the program in a SQL Database, and the program output can be saved in the same Database.

Parse the received response from the server in the program and display the IP address if found.

It is possible to receive the record type from the user, and the program can also find other records besides A records.

# Third Part: Iterative Requests

DNS queries can be Recursive or Iterative to reach the final answer. The Recursive model is such that if a server does not have the desired record, it will find the record by communicating with other servers and deliver it to you. The Iterative type is such that the server does not have the desired record and gives you the address of another server to send your query to. Handling the second case is the goal of this section.
