import argparse
from btcp.server_socket import BTCPServerSocket
from btcp.btcp_socket import *

"""This exposes a constant bytes object called TEST_BYTES_128MIB which, as the
name suggests, is 128 MiB in size. You can send it, receive it, and check it
for equality on the receiving end.

Pycharm may complain about an unresolved reference. This is a lie. It simply
cannot deal with a python source file this large so it cannot resolve the
reference. Python itself will run it fine, though.

You can also use the file large_input.py as-is for file transfer.
"""
from large_input import TEST_BYTES_128MIB


def btcp_file_transfer_server():
    """This method should implement your bTCP file transfer server. We have
    provided a bare bones implementation: a command line argument parser and
    a normal sequence of
    - create the server socket
    - accept the connection
    - open the output file
    - loop to receive data and write to the file
        - upon disconnect, exit the loop
    - close

    If you start this server_app.py, and then the client_app.py, this will
    receive the client process' input file and write it to the output file.

    Our rudimentary bTCP sockets already achieve this *on a perfect network*,
    because they just chunk the data into bTCP segments. You can check that
    input and output are the same by using the `cmp` command, e.g. for the
    default filenames:
        `cmp large_input.py output.file`
    If they are the same, no output is given.
    If they differ it will tell you the location of the first difference.

    But because there is no window size negotiation, no checksums, no sequence
    numbers, etc yet, the receiving queue might overflow, reordered segments
    end up as reordered data, flipped bits remain flipped, etc.

    If you need to change anything, feel free to use helper methods.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--window",
                        help="Define bTCP window size",
                        type=int, default=200)
    parser.add_argument("-t", "--timeout",
                        help="Define bTCP timeout in milliseconds",
                        type=int, default=100)
    parser.add_argument("-o", "--output",
                        help="Where to store the file",
                        default="output.file")
    args = parser.parse_args()

    # Create a bTCP server socket
    s = BTCPSocket(args.window, args.timeout)
    s.bind(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)

    # Accept the connection. By default this doesn't actually do anything: our
    # rudimentary implementation relies on you starting the server before the
    # client and just dumps all segment contents directly into a file. No
    # handshake is performed.
    s.accept()

    # Actually open the output file. Warning: will overwrite existing files.
    with open(args.output, 'wb') as outfile:
        # Receive the first data. In python 3.8 and up, we can avoid doing this
        # before the loop *and* at the end of the loop by using the assignment
        # expression operator instead:
        # while recvdata := s.recv():
        recvdata = s.recv()
        while True:
            outfile.write(recvdata)
            # Read new data from the socket.
            recvdata = s.recv()
        # In our rudimentary implementation, an empty bytes object returned by
        # recv indicates disconnection, so if we exit the loop we can assume
        # disconnection. We then exit the with-block, automatically closing the
        # output file.

    # Clean up any state
    s.close()


if __name__ == "__main__":
    btcp_file_transfer_server()
