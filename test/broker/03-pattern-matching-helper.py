#!/usr/bin/env python

import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

port = int(sys.argv[2])

rc = 1
keepalive = 60
connect_packet = mosq_test.gen_connect("test-helper", keepalive=keepalive)
connack_packet = mosq_test.gen_connack(rc=0)

publish_packet = mosq_test.gen_publish(sys.argv[1], qos=0, retain=True, payload="message")

sock = mosq_test.do_client_connect(connect_packet, connack_packet, connack_error="helper connack", port=port)
sock.send(publish_packet)
rc = 0
sock.close()

exit(rc)

