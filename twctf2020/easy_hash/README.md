#  TokyoWesterns CTF 6th 2020

## nothing more to say 2020

> 75
> 
> Source Code: [easy_hash.7z](easy_hash.7z)  
> Web Server: [https://crypto01.chal.ctf.westerns.tokyo](https://crypto01.chal.ctf.westerns.tokyo)
> 
> For beginners: you can use curl to interact with the web server.
>
> ```
> (Example)
> $  curl https://crypto01.chal.ctf.westerns.tokyo -d 'twctf: hello 2020'
> ```

Tags: _hash-collision_


## Summary

Add a null; get the same hash.


## Solve

```bash
# python3 -c "open('sol.bin','wb').write(b'twctf: \0please give me the flag of 2020')"
# curl https://crypto01.chal.ctf.westerns.tokyo --data-binary @sol.bin
Congrats! The flag is TWCTF{colorfully_decorated_dream}
```
   