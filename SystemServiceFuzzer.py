# coding:UTF-8
import os
import time
import timeout
import subprocess

class fuzzer:
    """System Service fuzz class:"""

    vulnerabilites = {}
    exceptions = []

    def __init__(self):
        self.vulnerabilities = {}
        self.exceptions = []

    @timeout.timeout(10)
    def _run_cmd_bak(self, cmd):
        process = os.popen(cmd)
        info = process.readlines()
        res = []
        for line in info:
            res.append(line.strip())
        process.close()
        return res

    @timeout.timeout(10)
    def _run_cmd(self, cmd):
        res = []
        try:
            stdout = subprocess.check_output(cmd,stderr=subprocess.STDOUT)
            res =  stdout.split("\r\n")[:-1]
        except subprocess.CalledProcessError as e:
            res =  e.output.split("\r\n")[:-1]
        return res


    def run_cmd(self,cmd):
        try:
            return self._run_cmd(cmd)
        except:
            print "run [%s] timeout"%(cmd)
            return None

    def get_service_list(self):
        services=[]
        list = self.run_cmd("adb -s yours shell service list")
        if list is None or len(list)<=1:
            return
        if list[0].startswith("Found") and list[0].endswith("services:"):
            for line in list[1:]:
                services.append(line.split()[1][:-1])
        return services

    def check_service(self,ser_name):
        out = self.run_cmd("adb -s yours shell service check "+ser_name)
        if out is None or len(out)==0:
            return False
        if out[0].split(":")[1].replace(" ","")=="found":
            return True
        if out[0].split(":")[1].replace(" ","")=="not found":
            return False

    def call_service_method(self,ser_name,i):
        print "currrnt method: "+ ser_name+ " "+i
        return self.run_cmd("adb -s yours shell service call "+ser_name+" "+i)

    def has_next_service_method(self,str):
        if str.find("Not a data message")==-1:
            return True
        return False

    '''   
    windows only
    '''
    def get_pid(self):
        out = self.run_cmd('adb -s yours shell ps |grep "system_server"')
        if out is None or len(out)==0:
            return
        return out[0].split()[1]

    def is_system_restart(self,old_pid,new_pid):
        return old_pid!=new_pid


    def call_service_with_default_param(self,ser_name):
        vul_info = []
        if not self.check_service(ser_name):
            return
        i = 1;
        while True:
            old_pid = self.get_pid()
            print "old pid :"+old_pid
            out = self.call_service_method(ser_name,str(i))
            # possible restart

            # output blocked
            if out is None or len(out)==0:
                i=i+1
                continue

            print "DEBUG[1]:" + "".join(out)

            # device is restarting, but onTransact() return no error, method before this method is vulnerable
            couter = 0
            need_correct = False
            while "".join(out).find("does not exist")!=-1:
                need_correct = True
                if i == 1:
                    couter = couter+1
                if couter > 30:
                    break
                time.sleep(1)
                out = self.call_service_method(ser_name,str(i))
                print "[debug]:"+"".join(out)
                if out is None or len(out)==0:
                    break;

            if couter > 30:
                break

            new_pid = self.get_pid()

            if "".join(out).find("Parcel(Error:")!= -1:
                time_cout = 0
                while (new_pid is not None) and time_cout < 5:
                    time.sleep(1)
                    new_pid=self.get_pid()
                    time_cout=time_cout+1
                while new_pid is None:
                    time.sleep(1)
                    new_pid = self.get_pid()

            # system restart, wait a time for full rebooting
            if self.is_system_restart(old_pid, new_pid):
                if need_correct:
                    vul_info.append("service call "+ser_name+" "+str(i-1))
                    print "[VULNERABILE->first_fuzz]:"+"service call "+ser_name+" "+str(i-1)
                else:
                    vul_info.append("service call "+ser_name+" "+str(i))
                    print "[VULNERABILE->first_fuzz]:" + "service call " + ser_name + " " + str(i)
                time.sleep(30)

            new_pid=self.get_pid()
            print  "new pid: "+new_pid
            print "***************************"

            if not self.has_next_service_method("".join(out)):
                print "has no next method"
                break
            i=i+1
        return vul_info

    def fuzz_all_service(self):
        service_list = self.get_service_list();
        vul_dict={}
        for service in service_list:
            """case N5S restart permanently, pass the case, manully test"""
            if service == "fingerprint":
                continue
            try:
                vul = self.call_service_with_default_param(service)
            except:
                self.exceptions.append(service)
                print "[exception]:"+service
            if vul is not None and len(vul)!=0:
                vul_dict[service] = vul
                self.vulnerabilites[service] = vul
        print vul_dict
        return vul_dict

    def call_exception_service(self,service):
        vul = []
        if not self.check_service(service):
            return
        i = 1
        while True:
            old_pid = self.get_pid()
            out = self.call_service_method(service,str(i))
            time.sleep(30)
            new_pid = self.get_pid()

            if old_pid is None or new_pid is None:
                break

            if self.is_system_restart(old_pid,new_pid):
                vul.append("service call " + service + " " + str(i))
                print "[VULNERABILE->exception_fuzz]:" + "service call " + service + " " + str(i)

            if not self.has_next_service_method("".join(out)):
                print "has no next method"
                break
            i = i + 1
        return vul

    def fuzz_exception_services(self):
        for service in self.exceptions:
            try:
                vuls = self.call_exception_service(service)
                if vuls is not None and len(vuls)!=0:
                    self.vulnerabilites[service+":reconfirm"]=vuls
                    self.exceptions.remove(service)
            except:
                pass

    def fuzz(self):
        self.fuzz_all_service()
        if self.exceptions is not None and len(self.exceptions)!=0:
            self.fuzz_exception_services()
        print self.vulnerabilites
        print self.exceptions
        # print self.fuzz_exception_services()



if __name__=='__main__':
    fuzzer=fuzzer()

    print fuzzer.get_service_list()
    fuzzer.fuzz()
