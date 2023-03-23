from scapy.all import *
# by yael vaisberger 211526462
#a dns server using scapy
IP_0 = '0.0.0.0'
DST_IP = '8.8.8.8'
PORT = 8153
SOCKET_TIMEOUT = 1
TIMEOUT = 1
MAX_MSG_LENGTH = 1024
FIXED_RESPONSE = "HTTP/1.1 200 OK\r\n"
DNSRR = "DNS Resource Record"


# a function that creates a html response with a list of all the found address
def creat_html_response(address_lst):
    html_body = """<html>
    <head></head>
    <body>
    </body>
    </html>"""
    data = ''
    for ip in address_lst:  # adds all address
        data = data + """<p>""" + ip + """<p>""" + '\n'
    html_txt = html_body[:25] + data + html_body[25:]
    return html_txt


# a function that creates a dns query request to find all ip address
def creat_dns_qr(url):
    ip_list = []
    found = False
    ip = IP(dst="8.8.8.8")
    upd = UDP(sport=12345, dport=53)
    dns = DNS(rd=1, qd=DNSQR(qtype="A", qname=url))
    r = sr1((ip / upd / dns), timeout=TIMEOUT)
    for pkt in range(r[DNS].ancount):  # iterates throw all packages to seek the ip address
        if r[DNSRR][pkt].type == 1:
            ip_list.append(r[DNSRR][pkt].rdata)
    if ip_list:
        found = True
    return ip_list, found


# checks if ip is according to protocol
def check_ip(address):
    txt = address.split('.')
    if len(txt) != 4:
        return False
    for num in txt:
        if num.isdigit() == False or int(num) > 256:
            return False
    return True

# a function that creates a reverse mapping dns request
def reverse_adr(address):
    ip_check = check_ip(address)
    if not ip_check:
        return "Invalid IP Address"
    txt = address.split('.')
    rev = ''
    for num in txt:
        rev = '.' + num + rev
    rev = rev[1:] + ".in-addr.arpa"
    ip = IP(dst="8.8.8.8")
    upd = UDP(sport=12345, dport=53)
    dns = DNS(rd=1, qd=DNSQR(qtype="PTR", qname=rev))
    r = sr1((ip / upd / dns), timeout=TIMEOUT)
    rev_adr = "IP address not found"
    for pkt in range(r[DNS].ancount):
        if r[DNSRR][pkt].type == 12:
            rev_adr = r[DNSRR][pkt].rdata.decode()
    return rev_adr

# a function that handles the http request and sends a response accordingly
def handle_client_request(resource, client_socket):
    url = resource
    if 'reverse' in url:
        data = reverse_adr(url[8:])
    else:
        list_ip, found = creat_dns_qr(url)
        if found:
            data = creat_html_response(list_ip)
        else:
            data = url + " wrong domain"
    file_size = len(data)
    http_header = FIXED_RESPONSE + "Content-Length:" + str(file_size) + "\r\n"
    http_header = http_header + "Content-Type: text/html; charset=utf-8\r\n\r\n"
    http_response = http_header + data
    client_socket.send(http_response.encode())
    return


# Checks if request is a valid HTTP request and returns TRUE / FALSE and the requested URL
def validate_http_request(request):
    end_request = request.index("HTTP/1.1") + len("HTTP/1.1")
    url_len = request.split()
    length = len(url_len[1])
    if request[0:3] != 'GET':
        return False, ''
    if request[3] != ' ':
        return False, ''
    if request[4 + length] != ' ':
        return False, ''
    if url_len[2] != "HTTP/1.1":
        return False, ''
    if request[end_request:end_request + 2] != '\r\n':
        return False, ''
    end_dir = request.index("HTTP/1.1")
    return True, request[5:end_dir - 1]


#  Handles client requests: verifies client's requests are legal HTTP, calls function to handle the requests
def handle_client(client_socket):
    print('Client connected')
    # while client is connected
    while True:
        client_request = client_socket.recv(MAX_MSG_LENGTH).decode()
        valid_http, resource = validate_http_request(client_request)
        if valid_http:
            print('Got a valid HTTP request')
            handle_client_request(resource, client_socket)
            break
        else:
            print('Error: Not a valid HTTP request')
            break

    print('Closing connection')
    client_socket.close()


def main():
    # Opens a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP_0, PORT))
    server_socket.listen()
    print("Listening for connections on port {}".format(PORT))

    while True:
        client_socket, client_address = server_socket.accept()
        print('New connection received')
        print(str(client_address))
        CLIENT_ADR = client_address[1]
        client_socket.settimeout(SOCKET_TIMEOUT)
        try:
            handle_client(client_socket)
        except Exception as e:
            print(e)


if __name__ == "__main__":
    # Call the main handler function
    main()
# creat a dns qr and send and resive using srl1
