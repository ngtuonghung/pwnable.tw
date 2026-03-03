#!/bin/bash
echo $$ > /tmp/target_pid
exec env GLIBC_TUNABLES="glibc.malloc.tcache_count=0" ./bounty_program_patched