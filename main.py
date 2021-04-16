from servertool import DNSServer
from echo_server import PORT , HOST
import socket
OPTIONS_MENU = """
1.SINGLE QUERY
2.MULTIPLE QUERY WITH A .csv FILE
3.TEST CONNECTION
4.EXIT
"""

INVALID_OPTION = """
INVALID OPTION , ENTER A VALID OPTION
"""

FIELDS = "QUESTION\tANSWER\t\tTYPE"

    

def simple_query(*args):
    server = args[0]
    question = input('ENTER HOSTNAME: ')
    qtype = input('ENTER QUESTION TYPE: ')
    results = server.query(question , qtype)
    print(FIELDS)
    for result in results:
        print("{}\t{}\t\t{}".format(question,result[1],result[0]))            

    

def multiple_query(*args):
    server = args[0]
    csv_name = input('ENTER FILE NAME (default queries.csv): ') or 'queries.csv'
    csv_output = input('ENTER OUTPUT FILE NAME (default output.csv): ') or 'output.csv'
    print_result = input('PRINT RESULT ?[y/n]: ') == 'y'
    results = server.multiple_query(csv_name)
    if print_result:
        print(FIELDS)
        for result in results:
            print("{}\t{}\t\t{}".format(*result))    
            
            
def test_connection(*args):
    server :DNSServer = args[0]
    message = input('ENTER YOUR MESSAGE (HEXADECIMAL WITH EVEN CHAR NUMBER): ')
    try:
        print('response : {}'.format(server._send_udp_message(HOST ,PORT , message , False)))
    except socket.timeout:
        print('time out!!!')

def terminate(*args):
    exit()
    

OPTIONS = [
    simple_query,
    multiple_query,
    test_connection,
    terminate
]



if __name__ == '__main__':
    default_root = '198.41.0.4'
    is_ipv6 = False
    root = input(f'ENTER YOUR ROOT SERVER OR PRESS ENTER TO USE DEFAULT SERVER ({default_root}): ') or default_root
    if root != '198.41.0.4':
        is_ipv6 = input(f'ENTER IP VERSION (6 or 4): ') == '6'
    
    server = DNSServer( root, 53 , is_ipv6=is_ipv6)
    while True:
        try:
            option = int(input(OPTIONS_MENU)) - 1
            OPTIONS[option](server)
        except IndexError:
            print(INVALID_OPTION)
            
            
        
        
    
    