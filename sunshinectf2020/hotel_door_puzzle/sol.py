#!/usr/bin/python3

import angr, time, io

FIND_ADDR=0x4022c1
t=time.time()
binary = open('./hotel_key_puzzle','rb').read()
proj = angr.Project(io.BytesIO(binary),auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.DFS())
simgr.explore(find=FIND_ADDR)
print(time.time() - t,end=" seconds\n")
print((simgr.found[0].posix.dumps(0)).split(b'\0')[0])
