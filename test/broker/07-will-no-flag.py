#!/usr/bin/env python

# Test whether a connection is disconnected if it sets the will flag but does
# not provide a will payload.

import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import struct
import mosq_test

rc = 1
keepalive = 10
connect_packet = mosq_test.gen_connect("will-no-payload", keepalive=keepalive, will_topic="will/topic", will_qos=1, will_retain=True)
b = list(struct.unpack("B"*len(connect_packet), connect_packet))

bmod = b[0:len(b)-2]
bmod[1] = bmod[1] - 2 # Reduce remaining length by two to remove final two payload length values

connect_packet = struct.pack("B"*len(bmod), *bmod)

port = mosq_test.get_port()
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, "", port=port)
    sock.close()
    rc = 0
finally:
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde)

exit(rc)

