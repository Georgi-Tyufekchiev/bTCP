import argparse
import time
from btcp.client_socket import BTCPClientSocket
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


def btcp_file_transfer_client():
    """This method should implement your bTCP file transfer client. We have
    provided a bare bones implementation: a command line argument parser and
    a normal sequence of
    - create the client socket
    - connect
    - open the file
    - loop to send all data in the file
    - shutdown / disconnect
    - close

    If you start the server_app.py, and then this client_app.py, this will
    transfer the input file to the server process.

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
                        type=int, default=100)
    parser.add_argument("-t", "--timeout",
                        help="Define bTCP timeout in milliseconds",
                        type=int, default=100)
    parser.add_argument("-i", "--input",
                        help="File to send",
                        default="large_input.py")
    args = parser.parse_args()

    # Create a bTCP client socket with the given window size and timeout value
    s = BTCPSocket(args.window, args.timeout)
    s.bind(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

    # Connect. By default this doesn't actually do anything: our rudimentary
    # implementation relies on you starting the server before the client,
    # and just dumps the entire file into the network immediately.
    s.connect()

    # Actually open the file, read the file, and send the data.
    with open(args.input, 'rb') as infile:
        # I'm reading the file in 1 MiB chunks.
        chunksize = 1_024_000

        # Read the first chunk. In python 3.8 and up, we can avoid doing this
        # before the loop *and* at the end of the loop by using the assignment
        # expression operator instead:
        # while data := bytearray(infile.read(chunksize)):.
        #
        # For efficiency, I'm using a mutable bytearray. This is much faster
        # than re-assigning the non-sent slice after every call to send.
        data = bytearray(infile.read(chunksize))

        # Outer loop: while new data was successfully read from file.
        while data:
            # Loop until all data read was successfully sent. I've added a
            # small timeout to allow the sendbuffer to empty out a bit before
            # trying to send more.
            while data:
                sent_bytes = s.send(data)
                del data[:sent_bytes]
                time.sleep(0.00005)
            # In outer loop: Read new data.
            data = bytearray(infile.read(chunksize))

        # If we exit this loop, all data has been read. We exit the with-block
        # which automatically closes the input file.

    # Disconnect, since we're done reading the file and done sending.
    # Note that by default this doesn't do *anything*.
    sleep(10)
    s.shutdown()

    # Clean up any state
    s.close()


if __name__ == "__main__":
    btcp_file_transfer_client()
