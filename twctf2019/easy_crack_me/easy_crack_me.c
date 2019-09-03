
undefined8 FUN_00400747(int param_1,long param_2)

{
  char cVar1;
  char *__s;
  int iVar2;
  undefined8 uVar3;
  size_t sVar4;
  char *pcVar5;
  long lVar6;
  undefined8 *puVar7;
  long in_FS_OFFSET;
  byte bVar8;
  int local_1b8;
  int local_1b4;
  int local_1b0;
  uint local_1ac;
  int local_1a8;
  int local_1a4;
  int local_1a0;
  uint local_19c;
  int local_198;
  int local_194;
  int local_190;
  int local_18c;
  char *local_188;
  undefined8 local_168;
  undefined8 local_160;
  undefined8 local_158;
  undefined8 local_150;
  undefined8 local_148;
  undefined8 local_140;
  undefined8 local_138;
  undefined8 local_130;
  undefined8 local_128;
  undefined8 local_120;
  undefined8 local_118;
  undefined8 local_110;
  undefined8 local_108;
  undefined8 local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8 [16];
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  bVar8 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 == 2) {
    __s = *(char **)(param_2 + 8);
    sVar4 = strlen(__s);
    if (sVar4 != 0x27) {
      puts("incorrect");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    iVar2 = memcmp(__s,"TWCTF{",6);
    if ((iVar2 != 0) || (__s[0x26] != '}')) {
      puts("incorrect");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    local_e8 = 0;
    local_e0 = 0;
    local_d8 = 0;
    local_d0 = 0;
    local_c8 = 0;
    local_c0 = 0;
    local_b8 = 0;
    local_b0 = 0;
    local_28 = 0x3736353433323130;
    local_20 = 0x6665646362613938;
    local_1b8 = 0;
    while (local_188 = __s, local_1b8 < 0x10) {
      while (pcVar5 = strchr(local_188,(int)*(char *)((long)&local_28 + (long)local_1b8)),
            pcVar5 != (char *)0x0) {
        *(int *)((long)&local_e8 + (long)local_1b8 * 4) =
             *(int *)((long)&local_e8 + (long)local_1b8 * 4) + 1;
        local_188 = pcVar5 + 1;
      }
      local_1b8 = local_1b8 + 1;
    }
    iVar2 = memcmp(&local_e8,&DAT_00400f00,0x40);
    if (iVar2 != 0) {
      puts("incorrect");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    local_168 = 0;
    local_160 = 0;
    local_158 = 0;
    local_150 = 0;
    local_148 = 0;
    local_140 = 0;
    local_138 = 0;
    local_130 = 0;
    local_1b4 = 0;
    while (local_1b4 < 8) {
      local_1b0 = 0;
      local_1ac = 0;
      local_1a8 = 0;
      while (local_1a8 < 4) {
        local_1b0 = local_1b0 + (int)__s[(long)local_1a8 + (long)(local_1b4 << 2) + 6];
        local_1ac = local_1ac ^ (int)__s[(long)local_1a8 + (long)(local_1b4 << 2) + 6];
        local_1a8 = local_1a8 + 1;
      }
      *(int *)((long)&local_168 + (long)local_1b4 * 4) = local_1b0;
      *(uint *)((long)&local_148 + (long)local_1b4 * 4) = local_1ac;
      local_1b4 = local_1b4 + 1;
    }
    local_128 = 0;
    local_120 = 0;
    local_118 = 0;
    local_110 = 0;
    local_108 = 0;
    local_100 = 0;
    local_f8 = 0;
    local_f0 = 0;
    local_1a4 = 0;
    while (local_1a4 < 8) {
      local_1a0 = 0;
      local_19c = 0;
      local_198 = 0;
      while (local_198 < 4) {
        local_1a0 = local_1a0 + (int)__s[(long)(local_198 << 3) + (long)local_1a4 + 6];
        local_19c = local_19c ^ (int)__s[(long)(local_198 << 3) + (long)local_1a4 + 6];
        local_198 = local_198 + 1;
      }
      *(int *)((long)&local_128 + (long)local_1a4 * 4) = local_1a0;
      *(uint *)((long)&local_108 + (long)local_1a4 * 4) = local_19c;
      local_1a4 = local_1a4 + 1;
    }
    iVar2 = memcmp(&local_168,&DAT_00400f40,0x20);
    if ((iVar2 != 0) || (iVar2 = memcmp(&local_148,&DAT_00400f60,0x20), iVar2 != 0)) {
      puts("incorrect");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    iVar2 = memcmp(&local_128,&DAT_00400fa0,0x20);
    if ((iVar2 != 0) || (iVar2 = memcmp(&local_108,&DAT_00400f80,0x20), iVar2 != 0)) {
      puts("incorrect");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    lVar6 = 0x10;
    puVar7 = local_a8;
    while (lVar6 != 0) {
      lVar6 = lVar6 + -1;
      *puVar7 = 0;
      puVar7 = puVar7 + (ulong)bVar8 * 0x1ffffffffffffffe + 1;
    }
    local_194 = 0;
    while (local_194 < 0x20) {
      cVar1 = __s[(long)local_194 + 6];
      if ((cVar1 < '0') || ('9' < cVar1)) {
        if ((cVar1 < 'a') || ('f' < cVar1)) {
          *(undefined4 *)((long)local_a8 + (long)local_194 * 4) = 0;
        }
        else {
          *(undefined4 *)((long)local_a8 + (long)local_194 * 4) = 0x80;
        }
      }
      else {
        *(undefined4 *)((long)local_a8 + (long)local_194 * 4) = 0xff;
      }
      local_194 = local_194 + 1;
    }
    iVar2 = memcmp(local_a8,&DAT_00400fc0,0x80);
    if (iVar2 != 0) {
      puts("incorrect");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    local_190 = 0;
    local_18c = 0;
    while (local_18c < 0x10) {
      local_190 = local_190 + (int)__s[(long)((local_18c + 3) * 2)];
      local_18c = local_18c + 1;
    }
    if (local_190 != 0x488) {
      puts("incorrect");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    if ((((__s[0x25] != '5') || (__s[7] != 'f')) || (__s[0xb] != '8')) ||
       (((__s[0xc] != '7' || (__s[0x17] != '2')) || (__s[0x1f] != '4')))) {
      puts("incorrect");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    printf("Correct: %s\n",__s);
    uVar3 = 0;
  }
  else {
    fwrite("./bin flag_is_here",1,0x12,stderr);
    uVar3 = 1;
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

