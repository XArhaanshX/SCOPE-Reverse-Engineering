# Spawn wine (so we are its ancestor for /proc/pid/mem), wait, dump the Windows process's memory.
import subprocess, time, os, sys, re
exe = sys.argv[1]; wait = float(sys.argv[2]); out = sys.argv[3]
os.makedirs(out, exist_ok=True)
p = subprocess.Popen(['wine', exe], stdin=subprocess.PIPE, stdout=open(out + '/stdout.txt', 'wb'), stderr=subprocess.STDOUT)
time.sleep(wait)
target = None
for pid in os.listdir('/proc'):
    if pid.isdigit():
        try:
            cmd = open(f'/proc/{pid}/cmdline', 'rb').read()
        except OSError:
            continue
        if exe.encode() in cmd and b'wineserver' not in cmd:
            maps = open(f'/proc/{pid}/maps').read()
            if '00400000-' in maps:
                target = pid
print('target pid', target)
regions = []
with open(f'/proc/{target}/maps') as m, open(f'/proc/{target}/mem', 'rb', 0) as mem:
    for line in m:
        a, perm = line.split()[:2]
        lo, hi = (int(x, 16) for x in a.split('-'))
        if 'r' not in perm or hi - lo > 0x10000000 or lo >= 0x7f0000000000:
            continue
        try:
            mem.seek(lo); data = mem.read(hi - lo)
        except OSError:
            continue
        fn = f'{out}/{lo:012x}-{hi:012x}-{perm}.bin'
        open(fn, 'wb').write(data); regions.append(line.strip())
open(out + '/maps.txt', 'w').write('\n'.join(regions))
print(len(regions), 'regions dumped')
p.kill(); subprocess.run(['wineserver', '-k'])
