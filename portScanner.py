#!/user/bin/python3
import nmap
import socket

nm = nmap.PortScanner()
nm.scan('192.168.1.1-7', arguments='-sS -T4')

# tomamos la lista de hosts
listado_host = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
listado_up = []

# tomamos solo los que están 'up'
for host, status in listado_host:
        if status in 'up':
            listado_up.append(host)

for h in listado_up:
        print('IP: {}'.format(h))
        contador = 0
        if nm[h].hostname() == '':
                print('Hostname: no se pudo obtener nombre.')
        else:
                print('Hostname: {}'.format(nm[h].hostname()))
        print('-----------------------')
        for proto in nm[h].all_protocols():
                print('Protocolo: {proto}'.format(proto=proto.upper()))
                lport = nm[h][proto].keys()
                for port in lport:
                        print('puerto: %s\testado: %s\tservicio: %s' % (port, nm[h][proto][port]['state'], nm[h][proto][port]['name']))
        print('=======================')
