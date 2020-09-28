#!/usr/bin/env python3

import angr, time, claripy

t=time.time()
BINARY='./jack'
proj = angr.Project(BINARY, auto_load_libs=False)
print("Entry: 0x%x" % proj.entry)
FIND=0x00401489
input_len=16
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]
flag = claripy.Concat(*flag_chars)

state = proj.factory.entry_state(args=[BINARY], stdin=flag)

for k in flag_chars:
	state.solver.add(k < 0x7f)
	state.solver.add(k > 0x20)

simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.DFS())
simgr.explore(find=FIND)
print(simgr.found[0].posix.dumps(0))
print(time.time() - t, "seconds")
