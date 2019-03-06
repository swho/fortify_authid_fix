# coding=utf-8
import glob
import os
import re

import chardet


class FortifyDummyFix:

    def __init__(self, target):
        self.target = target
        self.v_process = 0

    def log(self, msg):
        if self.target:
            self.target.log(msg)
        else:
            print(msg)

    def do(self, argv):
        dir_proc = '\\Procedures\\*.*'
        dir_package = '\\Packages\\*.*'

        self.log('*****程序開始*****')
        self.log('*****自動SQL Fortify修改程式(AUTHID DEFINER)*****')
        self.log('*****不保證SQL程式運作正常，請compile後檢查狀態，但保證不會有任何實際漏洞被修正*****')
        self.log('*****目標資料夾:{0}*****'.format(argv))
        if len(argv) == 0:
            self.log('*****程序中止*****')
            exit(0)

        dir_proc = argv + dir_proc
        dir_package = argv + dir_package

        def get_upper(p_line=''):
            return p_line.upper()

        v_error = []
        v_change = []
        v_skip = []
        v_skip_res = []

        v_total = len(glob.glob(dir_proc)) + len(glob.glob(dir_package))
        v_current = 0
        for v_dir in [dir_proc, dir_package]:
            files = glob.glob(v_dir)
            for file in files:
                try:
                    v_current += 1
                    if v_total > 0:
                        self.v_process = v_current / v_total * 100

                    self.log(os.path.abspath(file))
                    v_encoding = chardet.detect(open(file, "rb").read())
                    v_enc = v_encoding.get('encoding')
                    if v_enc == 'GB2312':
                        v_enc = 'MS950'
                    self.log(v_enc)

                    with open(file, 'r', encoding=v_enc) as v_f:
                        # with open(file, 'r') as v_f:
                        v_lines = v_f.readlines()

                    v_start = False
                    v_found = False
                    v_already = False
                    v_replace = ''

                    for row, line in enumerate(v_lines):
                        v_reason = '?'
                        if not v_found:
                            if line.strip().startswith("--"):
                                continue
                            if get_upper(line).strip().startswith("CREATE"):
                                v_start = True
                            if v_start:
                                for v_keyword in ['PIPELINED', 'IS', 'AS']:
                                    if re.match(r'(.*)COMPILE JAVA SOURCE (.*)', line, re.I):
                                        v_found = True
                                        v_already = True
                                        v_replace = line
                                        v_reason = 'JAVA SOURCE'
                                    elif re.match(r'(.*)AUTHID (.*)', line, re.I):
                                        v_found = True
                                        v_already = True
                                        v_replace = line
                                        v_reason = '已經定義'
                                    elif re.match(r'^' + v_keyword + r'\s.*', line, re.I):
                                        v_replace = 'AUTHID DEFINER ' + line
                                        v_found = True
                                    elif re.match(r'(.*)\s' + v_keyword + r'(\s$|(\s.+\s$))', line, re.I):
                                        v_replace = re.sub(r'(.*)\s' + v_keyword + r'(\s$|(\s.+\s$))',
                                                           r'\1 AUTHID DEFINER ' + v_keyword + r' \2', line, flags=re.I)
                                        v_found = True
                                    elif re.match(r'^' + v_keyword + r'\s', line, re.I):
                                        v_replace = 'AUTHID DEFINER ' + line
                                        v_found = True
                                    if v_found:
                                        self.log(v_replace)
                                        break
                        if v_found:
                            if v_replace == v_lines[row]:
                                v_found = False
                            v_lines[row] = v_replace
                            break

                    if v_already:
                        v_skip.append(os.path.abspath(file))
                        v_skip_res.append(v_reason)
                        self.log('*****SKIP*****')
                    elif not v_found:
                        v_error.append(os.path.abspath(file))
                        self.log('*****ERROR*****  CREATE:' + str(v_start))
                    else:
                        v_change.append(os.path.abspath(file))
                        v_full = ''
                        with open(file, 'w', encoding=v_enc) as v_f:
                            # with open(file, 'w') as v_f:
                            for v_inline in v_lines:
                                v_f.write(v_inline)
                                v_full += v_inline
                            v_full = v_full.strip()
                            if v_full[-1] != '/':
                                v_f.write('\r\n/')
                                self.log('Append / to the end.')
                except:
                    v_error.append(os.path.abspath(file))
                    # self.log(' critical error!', sys.exc_info()[0])
        self.v_process = 0
        self.log('-------------------------------------------------------------------------------')
        self.log('-------------------------------------------------------------------------------')
        self.log('-------------------------------------------------------------------------------')
        self.log('Success List:')
        for v_chgmsg in v_change:
            self.log('@' + v_chgmsg)
        self.log('-------------------------------------------------------------------------------')
        self.log('Skip List:')
        for v_tmp in range(0, len(v_skip)):
            self.log('[' + v_skip_res[v_tmp] + ']@' + v_skip[v_tmp])
        self.log('-------------------------------------------------------------------------------')
        self.log('Error List:')
        for v_errmsg in v_error:
            self.log(v_errmsg)
        self.log('-------------------------------------------------------------------------------')
        self.log('Success count:' + str(len(v_change)))
        self.log('Skip count:' + str(len(v_skip)))
        self.log('Error count:' + str(len(v_error)))
        self.log('*****程序結束*****')
# it = FortifyDummyFix(None)
# it.do(sys.argv[1:])
