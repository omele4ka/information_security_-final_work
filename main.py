import nmap


def scan_for_vulnerabilities(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sV --script vulners')

    for host in nm.all_hosts():
        print(f'Scan results for host: {host}')
        for proto in nm[host].all_protocols():
            print(f'Protocol: {proto}')
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
                if 'script' in nm[host][proto][port]:
                    for script in nm[host][proto][port]['script']:
                        print(f"\t{script}: {nm[host][proto][port]['script'][script]}")


if __name__ == '__main__':
    target_host = input('Enter target host: ')
    scan_for_vulnerabilities(target_host)
