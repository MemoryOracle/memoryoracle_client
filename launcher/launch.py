#!/usr/bin/env python
# -*- encoding UTF-8 -*-

import subprocess
import sys
import tempfile
import os


class MemoryOracleClient(object):

    def __init__(self):
        self.args = "--undefined--"

    def launch(self):

        vp = ValgrindProcess().launch()

        print("Launching gdb")
        pid = vp.pid
        self.args = ["/usr/bin/gdb"]
        self.args += ['-ex', 'target remote | vgdb --pid={}'.format(pid)]
        self.args += ['-ex', 'source default_args.gdb']
        self.args += ['--args', " ".join(sys.argv[1:])]
        subprocess.call(self.args,
                        stdin=sys.stdin,
                        stdout=sys.stdout,
                        shell=False
                        )
        try:
            vp.wait(1)
        except subprocess.TimeoutExpired as e:
            print(e)
            print("closing!")
            vp.terminate()
            try:
                vp.wait(1)
            except subprocess.TimeoutExpired as e2:
                print(e2)
                print("terminating!")
                vp.kill()


class ValgrindProcess(object):

    def __init__(self):
        self.valgrindTextLog = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.valgrindXMLLog = tempfile.NamedTemporaryFile(mode='w', delete=False)
        print("Valgrind logging to ", self.valgrindTextLog.name)
        print("Valgrind logging xml to ", self.valgrindXMLLog.name)

    def launch(self):
        valgrindArgs = ["/usr/bin/valgrind",
                        "-v",
                        "--vgdb=full",
                        "--vgdb-error=0",
                        "--log-file={}".format(self.valgrindTextLog.name),
                        "--track-fds=yes",
                        "--vgdb-stop-at=all",
                        "--xml=yes",
                        "--xml-file={}".format(self.valgrindXMLLog.name),
                        "--demangle=yes",
                        "--show-leak-kinds=all",
                        "--leak-check=full"
                       ]
        exe = ["./" + os.path.relpath(sys.argv[1])]
        valgrindArgs.extend(exe + sys.argv[2:])
        print(valgrindArgs)

        valgrindProcess = subprocess.Popen(valgrindArgs,
                                        stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL,
                                        shell=False
                                        )
        print("Writing pid!")
        return valgrindProcess


class InferiorTerminal(object):

    def __init__(self):
        self.valgrindTextLog = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.valgrindXMLLog = tempfile.NamedTemporaryFile(mode='w', delete=False)
        print("Valgrind logging xml to ", self.valgrindXMLLog.name)

    def launch(self):
        self.term = ["terminator", "-x"]
        valgrindArgs = ["/usr/bin/valgrind",
                        "-v",
                        "--vgdb=full",
                        "--vgdb-error=0",
                        "--log-file={}".format(self.valgrindTextLog.name),
                        "--track-fds=yes",
                        "--vgdb-stop-at=all",
                        "--xml=yes",
                        "--xml-file={}".format(self.valgrindXMLLog.name),
                        "--demangle=yes",
                        "--show-leak-kinds=all",
                        "--leak-check=full"
                       ]
        exe = ["./" + os.path.relpath(sys.argv[1])]
        valgrindArgs.extend(exe + sys.argv[2:])
        print(valgrindArgs)
        valgrindArgs = " ".join(valgrindArgs)
        command = self.term + [valgrindArgs]
        print(command)
        subprocess.Popen(" ".join(command),
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         shell=True
                        )


if __name__ == "__main__":
    # MemoryOracleProcess().launch()
    InferiorTerminal().launch()
