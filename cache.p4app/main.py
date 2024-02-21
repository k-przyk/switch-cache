from p4app import P4Mininet
from mininet.topo import SingleSwitchTopo
import sys
import time

topo = SingleSwitchTopo(2)
net = P4Mininet(program='cache.p4', topo=topo)
net.start()

s1, h1, h2 = net.get('s1'), net.get('h1'), net.get('h2')

h1_ip = net.get('h1').intfs[0].IP() # Server
h1_mac = net.get('h1').intfs[0].MAC()

h2_ip = net.get('h2').intfs[0].IP() # Client
h2_mac = net.get('h2').intfs[0].MAC()

cache = {3: 33}

# Populate IPv4 forwarding table
s1.insertTableEntry(
    table_name="MyIngress.ipv4_lpm",
    match_fields={'hdr.ipv4.dstAddr': [h1_ip, 32]},
    action_name="MyIngress.ipv4_forward",
    action_params={
        'dstAddr': h1_mac,
        'port': 1
    }
)

s1.insertTableEntry(
    table_name="MyIngress.ipv4_lpm",
    match_fields={'hdr.ipv4.dstAddr': [h2_ip, 32]},
    action_name="MyIngress.ipv4_forward",
    action_params={
        'dstAddr': h2_mac,
        'port': 2
    }
)

# Populate the cache table
for k, v in cache.items():
    s1.insertTableEntry(
        table_name="MyIngress.cache",
        match_fields={'hdr.request.key': k},
        action_name="MyIngress.cache_hit",
        action_params={
            'value': v
        }
    )  


# Now, we can test that everything works

# Start the server with some key-values
server = h1.popen('./server.py 1=11 2=22', stdout=sys.stdout, stderr=sys.stdout)
time.sleep(0.4) # wait for the server to be listenning

out = h2.cmd('./client.py 10.0.0.1 1') # expect a resp from server
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 1') # expect a value from switch cache (registers)
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 2') # resp from server
assert out.strip() == "22"
out = h2.cmd('./client.py 10.0.0.1 3') # from switch cache (table)
assert out.strip() == "33"
out = h2.cmd('./client.py 10.0.0.1 123') # resp not found from server
assert out.strip() == "NOTFOUND"

print('Thank you Amirmohammad!')
server.terminate()
