#!/usr/bin/env python3

import angr, time, claripy

BINARY='./welcome'
t=time.time()
proj = angr.Project(BINARY, auto_load_libs=False)
FIND=0x40165d
input_len=16
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]
flag = claripy.Concat( *flag_chars  + [claripy.BVV(b'\n')])
state = proj.factory.entry_state(args=[BINARY], stdin=flag)

for k in flag_chars:
	state.solver.add(k < 0x33)
	state.solver.add(k > 0x30)

simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.DFS())
simgr.explore(find=FIND)
print(simgr.found[0].posix.dumps(0))
print(time.time() - t, "seconds")
