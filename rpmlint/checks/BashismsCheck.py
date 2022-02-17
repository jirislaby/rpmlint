import stat
import subprocess
import time

from rpmlint.checks.AbstractCheck import AbstractFilesCheck
from rpmlint.helpers import ENGLISH_ENVIROMENT


class BashismsCheck(AbstractFilesCheck):
    def __init__(self, config, output):
        super().__init__(config, output, r'.*')
        self.use_threads = True
        self._detect_early_fail_option()
        self.file_cache = {}
        self.dtime = 0
        self.btime = 0

    def __del__(self):
        print(f'BashismsCheck: dtime={self.dtime:.2f} s btime={self.btime:.2f} s')

    def _detect_early_fail_option(self):
        output = subprocess.check_output(['checkbashisms', '--help'],
                                         shell=True, encoding='utf8')
        # FIXME: remove in the future
        self.use_early_fail = '[-e]' in output

    def check_file(self, pkg, filename):
        root = pkg.dirName()
        pkgfile = pkg.files[filename]
        filepath = root + filename

        # We only care about the real files that state they are shell scripts
        if not (stat.S_ISREG(pkgfile.mode) and
                pkgfile.magic.startswith('POSIX shell script')):
            return

        # There are package likes Linux kernel where there are common
        # shell scripts present in multiple packages
        # (kernel-source, kernel-source-vanilla).
        if pkgfile.md5 not in self.file_cache:
            self.file_cache[pkgfile.md5] = list(self.check_bashisms(pkg, filepath, filename))

        for warning in self.file_cache[pkgfile.md5]:
            self.output.add_info('W', pkg, warning, filename)

    def check_bashisms(self, pkg, filepath, filename):
        """
        Run dash and then checkbashism on file

        We need to see if it is valid syntax of bash and if there are no
        potential bash issues.
        Return a warning message or None if there is no problem.
        """
        print(f'BashismsCheck: checking {filename}')

        start = time.monotonic()
        try:
            r = subprocess.run(['dash', '-n', filepath],
                               stderr=subprocess.DEVNULL,
                               env=ENGLISH_ENVIROMENT)
            if r.returncode == 2:
                yield 'bin-sh-syntax-error'
            elif r.returncode == 127:
                raise FileNotFoundError(filename)
        except UnicodeDecodeError:
            pass

        now = time.monotonic()
        print(f'BashismsCheck: {filename} dash took {now-start:.2f} s')
        self.dtime += now - start
        start = now

        try:
            cmd = ['checkbashisms', filepath]
            # --early-fail option can rapidly speed up the check
            if self.use_early_fail:
                cmd.append('-e')
            r = subprocess.run(cmd,
                               stderr=subprocess.DEVNULL,
                               env=ENGLISH_ENVIROMENT)
            if r.returncode == 1:
                yield 'potential-bashisms'
            elif r.returncode == 2:
                raise FileNotFoundError(filename)
        except UnicodeDecodeError:
            pass

        now = time.monotonic()
        print(f'BashismsCheck: {filename} checkbashisms took {now-start:.2f} s')
        self.btime += now - start
