import binascii
import socket
import sys
from collections import OrderedDict
import re
from random import randint
from concurrent.futures import ThreadPoolExecutor
from itertools import chain
import csv
from db.models import (
    DNSRequest,
    DNSRecord
)
from peewee import DoesNotExist

class DNSServer:

    def __init__(self, root, port=53, is_ipv6=False):
        self.root = root
        self.port = port
        self.is_ipv6 = is_ipv6

    def _send_udp_message(self, root, port, message, is_ipv6):
        message = message.replace(" ", "").replace("\n", "")
        server_address = (root, port)
        with socket.socket(socket.AF_INET6 if is_ipv6 else socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5.0)
            sock.sendto(binascii.unhexlify(message), server_address)
            data, _ = sock.recvfrom(4096)
        return binascii.hexlify(data).decode("utf-8")

    def _build_message(self,
                       type="A", 
                       address="",
                       recursion=0 , 
                       is_query=0,
                       truncated=0):
        ID = randint(0, 65535)
        QR = is_query
        OPCODE = 0
        AA = 0
        TC = truncated
        RD = recursion
        RA = 0
        Z = 0
        RCODE = 0

        query_params = str(QR)
        query_params += str(OPCODE).zfill(4)
        query_params += str(AA) + str(TC) + str(RD) + str(RA)
        query_params += str(Z).zfill(3)
        query_params += str(RCODE).zfill(4)
        query_params = "{:04x}".format(int(query_params, 2))

        QDCOUNT = 1
        ANCOUNT = 0
        NSCOUNT = 0
        ARCOUNT = 0

        message = ""
        message += "{:04x}".format(ID)
        message += query_params
        message += "{:04x}".format(QDCOUNT)
        message += "{:04x}".format(ANCOUNT)
        message += "{:04x}".format(NSCOUNT)
        message += "{:04x}".format(ARCOUNT)
        addr_parts = address.split(".")
        for part in addr_parts:
            addr_len = "{:02x}".format(len(part))
            addr_part = binascii.hexlify(part.encode())
            message += addr_len
            message += addr_part.decode()

        message += "00"
        QTYPE = self._get_type(type)
        message += QTYPE
        QCLASS = 1
        message += "{:04x}".format(QCLASS)

        return message

    def _decode_message(self, message):

        ID = message[0:4]
        query_params = message[4:8]
        QDCOUNT = message[8:12]
        ANCOUNT = message[12:16]
        NSCOUNT = message[16:20]
        ARCOUNT = message[20:24]

        params = "{:b}".format(int(query_params, 16)).zfill(16)
        QPARAMS = OrderedDict([
            ("QR", params[0:1]),
            ("OPCODE", params[1:5]),
            ("AA", params[5:6]),
            ("TC", params[6:7]),
            ("RD", params[7:8]),
            ("RA", params[8:9]),
            ("Z", params[9:12]),
            ("RCODE", params[12:16])
        ])

        # Question section
        QUESTION_SECTION_STARTS = 24
        question_parts = self._parse_parts(
            message, QUESTION_SECTION_STARTS, [])

        QNAME = ".".join(
            map(lambda p: binascii.unhexlify(p).decode(), question_parts))

        QTYPE_STARTS = QUESTION_SECTION_STARTS + \
            (len("".join(question_parts))) + (len(question_parts) * 2) + 2
        QCLASS_STARTS = QTYPE_STARTS + 4

        QTYPE = message[QTYPE_STARTS:QCLASS_STARTS]
        QCLASS = message[QCLASS_STARTS:QCLASS_STARTS + 4]

        # Answer section
        ANSWER_SECTION_STARTS = QCLASS_STARTS + 4

        AUTHORATIVE_SECTION_START, answer_section = self._parse_section(
            message, int(ANCOUNT, 16), 'ANSWER', ANSWER_SECTION_STARTS)
        ADDITIONAL_SECTION_START, auth_section = self._parse_section(
            message, int(NSCOUNT, 16), 'AUTHORATIVE', ANSWER_SECTION_STARTS)
        _, add_section = self._parse_section(message, int(
            ARCOUNT, 16), 'ADDITIONAL', ADDITIONAL_SECTION_START)
        host_ip = dict()
        if len(auth_section) > 0:
            for record, aname_add in zip(list(auth_section.values())[0], list(add_section.keys())):
                host_ip[record[1]] = add_section[aname_add]
        answers = set()
        # print(answer_section)
        if len(answer_section) > 0:
            for value in answer_section.values():
                answers |= set(value)

        # print(host_ip)
        # print(answers)
        return answers, host_ip

    def _parse_section(self, message, NUM_ANSWERS, section_name, SECTION_STARTS):
        answers = OrderedDict()
        if NUM_ANSWERS > 0:
            for ANSWER_COUNT in range(NUM_ANSWERS):
                if (SECTION_STARTS < len(message)):
                    ANAME = message[SECTION_STARTS:SECTION_STARTS + 4]
                    ATYPE = message[SECTION_STARTS + 4:SECTION_STARTS + 8]
                    ACLASS = message[SECTION_STARTS + 8:SECTION_STARTS + 12]
                    TTL = int(message[SECTION_STARTS +
                              12:SECTION_STARTS + 20], 16)
                    RDLENGTH = int(
                        message[SECTION_STARTS + 20:SECTION_STARTS + 24], 16)
                    RDDATA = message[SECTION_STARTS +
                                     24:SECTION_STARTS + 24 + (RDLENGTH * 2)]

                    if ATYPE == self._get_type("A"):
                        octets = [RDDATA[i:i+2]
                                  for i in range(0, len(RDDATA), 2)]
                        RDDATA_decoded = ".".join(
                            list(map(lambda x: str(int(x, 16)), octets)))
                    elif ATYPE == self._get_type("AAAA"):
                        RDDATA_decoded = self._parse_ipv6(RDDATA)
                    else:
                        RDDATA_decoded = ".".join(map(lambda p: binascii.unhexlify(
                            p).decode('iso8859-1'), self._parse_parts(RDDATA, 0, [])))

                    SECTION_STARTS = SECTION_STARTS + 24 + (RDLENGTH * 2)

                try:
                    ATYPE
                except NameError:
                    None
                else:
                    try:
                        answers[ANAME].append(
                            (self._get_type(int(ATYPE, 16)), RDDATA_decoded))
                    except:
                        answers[ANAME] = [
                            (self._get_type(int(ATYPE, 16)), RDDATA_decoded)]

        return SECTION_STARTS, answers

    def _get_type(self, type):
        types = {
            0: "ERROR",
            1: "A",
            2: "NS",
            3: "MD",
            4: "MF",
            5: "CNAME",
            6: "SOA",
            7: "MB",
            8: "MG",
            9: "MR",
            10: "NULL",
            11: "WKS",
            12: "PTS",
            13: "HINFO",
            14: "MINFO",
            15: "MX",
            16: "TXT",
            28: "AAAA"
        }
        if isinstance(type, str):
            for key, val in types.items():
                if val == type:
                    return "{:04x}".format(key)

        return types[type]

    def _parse_ipv6(self, data):
        ip = ':'.join([data[i:i+4] for i in range(0, len(data), 4)])

        ip = ip.replace("0000",  "*")
        ip = re.sub(":0+", ":", ip)
        ip = re.sub(":\\*:\\*(:\\*)+:", '::', ip)
        ip = ip.replace("*", '0')
        return ip

    def _parse_parts(self, message, start, parts):
        part_start = start + 2
        part_len = message[start:part_start]

        if len(part_len) == 0:
            return parts

        part_end = part_start + (int(part_len, 16) * 2)
        parts.append(message[part_start:part_end])

        if message[part_end:part_end + 2] == "00" or part_end > len(message):
            return parts
        else:
            return self._parse_parts(message, part_end, parts)

    def query(self, host_name, qtype, recursion=0):
        records = DNSRecord.select(DNSRecord).where(DNSRecord.question == host_name , DNSRecord.Qtype == qtype)
        if len(records):
            answers = set([(record.Atype , record.answer) for record in records])
            return answers
        
        message = self._build_message(
            address=host_name, type=qtype, recursion=recursion)
        answers, explored = set(), set()

        def bfs(args):
            root, is_ipv6, answers = args[1], args[0], args[2]
            if root in explored:
                return
            explored.add(root)
            response = self._send_udp_message(
                root, self.port, message, is_ipv6=is_ipv6)
            answer_section, auth_section = self._decode_message(response)
            if len(answer_section):
                answers |= answer_section

            if len(auth_section):
                auth_ips = list(chain.from_iterable(auth_section.values()))
                with ThreadPoolExecutor() as executor:
                    executor.map(
                        bfs, [(record[0] == 'AAAA', record[1], answers) for record in auth_ips])

        bfs([self.is_ipv6, self.root, answers])
        
        try:
            req = DNSRequest.get(DNSRequest.question == host_name ,DNSRequest.type == qtype )
            req.req_count += 1
            if req.req_count == 3:
                req.delete_instance()
                if answers:
                    for answer in answers:
                        DNSRecord.create(question = host_name , answer=answer[1] , Atype = answer[0] , Qtype = qtype )
                        
            else:
                req.save()
            
        except DoesNotExist:
            DNSRequest.create(question = host_name ,type = qtype )
        
        return answers
    
    def _query_handler(self , args):
        return self.query(args[0] ,args[1])
    
    def multiple_query(self , csv_input , csv_output='output.csv'):
        with open(csv_input , 'r') as file:
            queries = csv.reader(file)
            fields = next(queries)
            results= [['QUESTION','ANSWER' , 'TYPE']]
            queries = list(queries)
            with ThreadPoolExecutor() as executor:
                for i,result in enumerate(executor.map(self._query_handler , queries)):
                    query = queries[i]
                    # print(query)
                    for record in result:
                        results.append([query[0] , record[1],record[0]])    
        with open(csv_output , 'w') as file:
            writer = csv.writer(file)
            writer.writerows(results)
        return results