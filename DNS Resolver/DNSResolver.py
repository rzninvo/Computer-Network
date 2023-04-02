import binascii
import socket
import sys
from collections import OrderedDict

def get_type(type):
    types = [
        "ERROR", # type 0 does not exist
        "A",
        "NS",
        "MD",
        "MF",
        "CNAME",
        "SOA",
        "MB",
        "MG",
        "MR",
        "NULL",
        "WKS",
        "PTS",
        "HINFO",
        "MINFO",
        "MX",
        "TXT"
    ]

    return "{:04x}".format(types.index(type)) if isinstance(type, str) else types[type]

class dns_message:
    def __init__(self, ID, header, counts, question, answer):
        self.ID = ID
        self.header = header
        self.counts = counts
        self.question = question
        self.answer = answer

    def build_encoded_message(self):
        message = ""
        message += "{:04x}".format(self.ID)
        message += self.header.encode_message_header()
        message += self.counts.encode_message_counts()
        message += self.question.encode_message_question()
        return message

    def decode_message(self, message):
        decoded_header = self.header.decode_message_header(message)
        decoded_counts = self.counts.decode_message_counts(message)
        decoded_question = self.question.decode_message_question(message)
        decoded_answer = decode_message_answers(message, int(decoded_header.RD, 16), decoded_question[1], decoded_counts.ANCOUNT, decoded_counts.NSCOUNT, decoded_counts.ARCOUNT)
        decoded_message = dns_message(message[0:4], decoded_header, decoded_counts, decoded_question[0], decoded_answer)
        return decoded_message

    def print_decoded_message(self):
        print("\nHEADER\n")
        print("ID = " + self.ID)
        print("QR = " + self.header.QR)
        print("OPCODE = " + self.header.OPCODE)
        print("AA = " + self.header.AA)
        print("TC = " + self.header.TC)
        print("RD = " + self.header.RD)
        print("RA = " + self.header.RA)
        print("Z = " + self.header.Z)
        print("RCODE= " + self.header.RCODE)
        print("\nCOUNTS\n")
        print("QDCOUNT = " + str(int(self.counts.QDCOUNT, 16)))
        print("ANCOUNT = " + str(int(self.counts.ANCOUNT, 16)))
        print("NSCOUNT = " + str(int(self.counts.NSCOUNT, 16)))
        print("ARCOUNT = " + str(int(self.counts.ARCOUNT, 16)))
        print("\nQUESTION\n")
        print("QNAME = " + self.question.NAME)
        print("QTYPE = " + get_type(int(self.question.TYPE, 16)))
        print("QCLASS = " + self.question.CLASS)
        answer = self.answer[0]
        for ANSWER_COUNT in range(self.answer[1]): 
            print("\nANSWER" + str(ANSWER_COUNT + 1) + "\n")
            print("NAME = " + answer[ANSWER_COUNT].NAME)
            print("TYPE = " + get_type(int(answer[ANSWER_COUNT].TYPE, 16)))
            print("CLASS = " + answer[ANSWER_COUNT].TYPE)
            print("TTL = " + str(answer[ANSWER_COUNT].TTL))
            print("RDLENGTH = " + str(answer[ANSWER_COUNT].RDLENGTH))
            print("RDDATA = " + answer[ANSWER_COUNT].RDDATA)
            print("RDDATA DECODED = " + answer[ANSWER_COUNT].RDDATA_decoded)

class dns_message_header:
    def __init__(self, QR, OPCODE, AA, TC, RD, RA, Z, RCODE):
        self.QR = QR
        self.OPCODE = OPCODE
        self.AA = AA
        self.TC = TC
        self.RD = RD
        self.RA = RA
        self.Z = Z
        self.RCODE = RCODE

    def encode_message_header(self):
        encoded_header = str(self.QR)
        encoded_header += str(self.OPCODE).zfill(4)
        encoded_header += str(self.AA) + str(self.TC) + str(self.RD) + str(self.RA)
        encoded_header += str(self.Z).zfill(3)
        encoded_header += str(self.RCODE).zfill(4)
        encoded_header = "{:04x}".format(int(encoded_header, 2))    
        return encoded_header 

    def decode_message_header(self, message):
        params = "{:b}".format(int(message[4:8], 16)).zfill(16)
        msg_header = dns_message_header(params[0:1], params[1:5], params[5:6], params[6:7], params[7:8], params[8:9]
            , params[9:12], params[12:16])
        return msg_header

class dns_message_counts:
    def __init__(self, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT):
        self.QDCOUNT = QDCOUNT
        self.ANCOUNT = ANCOUNT
        self.NSCOUNT = NSCOUNT
        self.ARCOUNT = ARCOUNT

    def encode_message_counts(self):
        encoded_counts = ""
        encoded_counts += "{:04x}".format(self.QDCOUNT)
        encoded_counts += "{:04x}".format(self.ANCOUNT)
        encoded_counts += "{:04x}".format(self.NSCOUNT)
        encoded_counts += "{:04x}".format(self.ARCOUNT)
        return encoded_counts

    def decode_message_counts(self, message):
        msg_counts = dns_message_counts(message[8:12], message[12:16], message[16:20], message[20:24])
        return msg_counts

class dns_message_question:
    def __init__(self, NAME, TYPE, CLASS):
        self.NAME = NAME
        self.TYPE = TYPE
        self.CLASS = CLASS

    def encode_message_question(self):
        encoded_question = ""
        addr_parts = self.NAME.split(".")
        for part in addr_parts:
            addr_len = "{:02x}".format(len(part))
            addr_part = binascii.hexlify(part.encode())
            encoded_question += addr_len
            encoded_question += addr_part.decode()

        encoded_question += "00"
        encoded_question += get_type(self.TYPE)
        encoded_question += "{:04x}".format(self.CLASS)
        return encoded_question

    def decode_message_question(self, message):
        QUESTION_SECTION_STARTS = 24
        question_parts = parse_parts(message, QUESTION_SECTION_STARTS, [])
    
        QNAME = ".".join(map(lambda p: binascii.unhexlify(p).decode(), question_parts))    

        QTYPE_STARTS = QUESTION_SECTION_STARTS + (len("".join(question_parts))) + (len(question_parts) * 2) + 2
        QCLASS_STARTS = QTYPE_STARTS + 4

        QTYPE = message[QTYPE_STARTS:QCLASS_STARTS]
        QCLASS = message[QCLASS_STARTS:QCLASS_STARTS + 4]
        msg_question = dns_message_question(QNAME, QTYPE, QCLASS)
        return (msg_question, QCLASS_STARTS + 4)

def parse_parts(message, start, parts):
        part_start = start + 2
        part_len = message[start:part_start]
    
        if len(part_len) == 0:
            return parts
    
        part_end = part_start + (int(part_len, 16) * 2)
        parts.append(message[part_start:part_end])

        if message[part_end:part_end + 2] == "00" or part_end > len(message):
            return parts
        else:
            return parse_parts(message, part_end, parts)

class dns_message_answer:
    def __init__(self, NAME, TYPE, CLASS, TTL, RDLENGTH, RDDATA, RDDATA_decoded):
        self.NAME = NAME
        self.TYPE = TYPE
        self.CLASS = CLASS
        self.TTL = TTL
        self.RDLENGTH =RDLENGTH
        self.RDDATA = RDDATA
        self.RDDATA_decoded = RDDATA_decoded

def decode_message_answers(message, RD, START, ANCOUNT, NSCOUNT, ARCOUNT):
    answers = []

    if (RD == 1):
        NUM_ANSWERS = max([int(ANCOUNT, 16), int(NSCOUNT, 16), int(ARCOUNT, 16)])
    else:
        if (int(ANCOUNT, 16) == 0):
            NUM_ANSWERS = int(ANCOUNT, 16) + int(NSCOUNT, 16) + int(ARCOUNT, 16)
        else:
            NUM_ANSWERS = int(ANCOUNT, 16)

    for ANSWER_COUNT in range(NUM_ANSWERS):
        if (START < len(message)):
            NAME = message[START:START + 4] # Refers to Question
            TYPE = message[START + 4:START + 8]
            CLASS = message[START + 8:START + 12]
            TTL = int(message[START + 12:START + 20], 16)
            RDLENGTH = int(message[START + 20:START + 24], 16)
            RDDATA = message[START + 24:START + 24 + (RDLENGTH * 2)]

            if TYPE == get_type("A"):
                octets = [RDDATA[i:i+2] for i in range(0, len(RDDATA), 2)]
                RDDATA_decoded = ".".join(list(map(lambda x: str(int(x, 16)), octets)))
            else:
                RDDATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), parse_parts(RDDATA, 0, [])))

            msg_answer = dns_message_answer(NAME, TYPE, CLASS, TTL, RDLENGTH, RDDATA, RDDATA_decoded)
            answers.insert(ANSWER_COUNT , msg_answer)
            START = START + 24 + (RDLENGTH * 2)

    return  (answers, NUM_ANSWERS)

def send_udp_message(message, address, port):
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")

def iterative_dns_search(message, address, port):
    response = send_udp_message(message.build_encoded_message(), address, port)
    decoded_response = message.decode_message(response)
    answer = decoded_response.answer[0]
    alength = int(decoded_response.counts.ANCOUNT, 16)
    ANSWER_COUNT = 0
    if alength == 0:
        for ANSWER_COUNT in range(decoded_response.answer[1]):
            try:
                if (not (any(c.isalpha() for c in  answer[ANSWER_COUNT].RDDATA_decoded))) and (answer[ANSWER_COUNT].RDDATA_decoded != ""):
                    print("FOUND ROOT SERVER " + answer[ANSWER_COUNT].RDDATA_decoded)
                    response = iterative_dns_search(message, answer[ANSWER_COUNT].RDDATA_decoded, port)
                    decoded_response = message.decode_message(response)
            finally:
                if (int(decoded_response.counts.ANCOUNT, 16) != 0): return response
                else: continue
    else:
        return response


message_header = dns_message_header(0, 0, 0, 0, 0, 0, 0, 0)
message_counts = dns_message_counts(1, 0, 0, 0)
message_question = dns_message_question("aut.ac.ir", "A", 1)
message = dns_message(43690, message_header, message_counts, message_question, 0)
print("Request:\n" + message.build_encoded_message())

# response = send_udp_message(message.build_encoded_message(), "1.1.1.1", 53)
# print("\nResponse:\n" + response)

# decoded_response = message.decode_message(response)
# decoded_response.print_decoded_message()
response = iterative_dns_search(message, "198.41.0.4", 53)
decoded_response = message.decode_message(response)
decoded_response.print_decoded_message()
