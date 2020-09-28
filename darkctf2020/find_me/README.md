# DarkCTF 2020

## linux/find-me

> 165 solves / 321 points
>
> Author: Wolfy
>
> Mr.Wolf was doing some work and he accidentally deleted the important file can you help him and read the file?
>
> Note: All players will get individual container.
>
> `ssh ctf@findme.darkarmy.xyz -p 10000 password: wolfie`

Tags: _linux_ _lsof_


## Summary

_lsof_ to find process with open file descriptor to deleted file (old trick).


## Session

```bash
# ssh ctf@findme.darkarmy.xyz -p 10000
The authenticity of host '[findme.darkarmy.xyz]:10000 ([35.228.161.195]:10000)' can't be established.
ECDSA key fingerprint is SHA256:MaHii9IeH1WtsGRLX02CyAoNfdL3KMPZVtfomXA1RBU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[findme.darkarmy.xyz]:10000,[35.228.161.195]:10000' (ECDSA) to the list of known hosts.
  ___           _      _
 |   \ __ _ _ _| |__  /_\  _ _ _ __ _  _
 | |) / _` | '_| / / / _ \| '_| '  \ || |
 |___/\__,_|_| |_\_\/_/ \_\_| |_|_|_\_, |
                                    |__/
ctf@findme.darkarmy.xyz's password:
DISCLAIMER: Please don't abuse the server !

These Tasks were done to practice some Linux

Author: wolfie, Contact me for any problems


** Please wait a little! Wolfie cooking the environment for you! Have Fun **

wolf1@275b5c99a2a3:/home/wolf1$ lsof | grep delete
tail     10 wolf1    3r   REG   0,50       20 779838 /home/wolf1/pass (deleted)
```

Note the process ID of `10`.

```bash
wolf1@275b5c99a2a3:/home/wolf1$ ls -l /proc/10/fd
total 0
lr-x------ 1 wolf1 wolf1 64 Sep 28 01:37 0 -> /dev/null
l-wx------ 1 wolf1 wolf1 64 Sep 28 01:37 1 -> /dev/null
l-wx------ 1 wolf1 wolf1 64 Sep 28 01:37 2 -> /dev/null
lr-x------ 1 wolf1 wolf1 64 Sep 28 01:37 3 -> '/home/wolf1/pass (deleted)'

wolf1@275b5c99a2a3:/home/wolf1$ cat /proc/10/fd/3
mysecondpassword123

wolf1@275b5c99a2a3:/home/wolf1$ ls -l /home
total 8
drwxr-xr-x 1 wolf1 wolf1 4096 Sep 28 01:37 wolf1
drwxr-x--- 1 root  wolf2 4096 Sep 26 21:02 wolf2

wolf1@275b5c99a2a3:/home/wolf1$ su - wolf2
Password:

wolf2@275b5c99a2a3:~$ find . -type f
./.bash_logout
./.bashrc
./.profile
./proc/g/nice_work

wolf2@275b5c99a2a3:~$ cat proc/g/nice_work
darkCTF{you are standing on the flag}

}!!!kr0w_3c1n_hha0w{FTCkrad

wolf2@275b5c99a2a3:~$ echo '}!!!kr0w_3c1n_hha0w{FTCkrad' | rev
darkCTF{w0ahh_n1c3_w0rk!!!}
```