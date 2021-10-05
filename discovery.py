import nmap

class NetworkDiscovery():

    def __init__(self):
        self.nm = nmap.PortScanner()
        self.hosts_list = []
    
    def host_list(self, network):
        self.nm.scan(hosts=network, arguments='-n -sP -PE -PA21,23,80,3389')
        self.hosts_list = [(x, self.nm[x]['status']['state']) for x in self.nm.all_hosts()]
        self.hosts_list.append('localhost')
        for host, status in self.hosts_list:
            print('host: '+ host + ' status: ' + status)
        
        
    def open_ports(self):
        for host, status in self.hosts_list:
            self.nm.scan(host, '22-9000')
            self.nm.scaninfo()
            self.nm.all_hosts()

            for host in self.nm.all_hosts():
                print('----------------------------------------------------')
                print('Host : %s (%s)' % (host, self.nm[host].hostname()))
                print('State : %s' % self.nm[host].state())
                for proto in self.nm[host].all_protocols():
                    print('----------')
                    print('Protocol : %s' % proto)
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        print('port : %s\tstate : %s' % (port, self.nm[host][proto][port]['state']))
                

if __name__ == "__main__":
    network_discovery = NetworkDiscovery()
    network_discovery.host_list('192.168.43.0/24')
    network_discovery.open_ports()
    pass
