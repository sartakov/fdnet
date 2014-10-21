#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
from rdflib.graph import Graph
from rdflib import URIRef, Literal, BNode, Namespace
from rdflib import RDF
from graphviz import Digraph
import pygraphviz as ppp
import os
import xlsxwriter
import argparse

version = "1.2.1"
sid=6000000
prefix=[]
g = Graph()

#globals
src_ip=[]
src_hwAddr=[]
dst_ip=[]
src_port=[]
dst_port=[]
src_prog=[]
dst_prog=[]


#for rules
u_src_hwAddr=[]
u_src_prog=[]
u_dst_prog=[]
u_dst_ip=[]
u_dst_port=[]
u_src_ip=[]

#overall
ret_src_ip=[]
ret_dst_ip=[]


def add_src_dst(s_ip, d_ip):
    global ret_src_ip;
    global ret_dst_ip;
    for i in range (0, len(ret_src_ip)):
	if ret_src_ip[i]==s_ip and d_ip in ret_dst_ip[i]:
	    return;
	elif ret_src_ip[i]==s_ip:
	    ret_dst_ip[i]=ret_dst_ip[i]+", "+d_ip;
	    return;
    ret_src_ip.append(s_ip)
    ret_dst_ip.append(d_ip)


def add_src_dst_port(s_ip, s_hw, s_port, d_ip, d_port):
    global u_src_hwAddr;
    global u_src_ip;
    global u_dst_ip;
    global u_src_port;
    global u_dst_port;
    for i in range (0, len(u_src_ip)):
	if u_src_ip[i]==s_ip and u_dst_ip[i]==d_ip:
	    u_dst_port[i]=u_dst_port[i]+", "+d_port;
	    return;
    u_src_ip.append(s_ip)
    u_src_hwAddr.append(s_hw)
    u_dst_ip.append(d_ip)
    u_dst_port.append(d_port)


def createParser ():
#parser
    parser = argparse.ArgumentParser(
            prog = 'fdnet',
            description = ''' Simple script for extranting various data from Formal Definet Network file.  ''',
            add_help = False
            )

    parent_group = parser.add_argument_group (title='Options')
    parent_group.add_argument ('--help', '-h', action='help', help='Help')
    parent_group.add_argument ('--version', action='version', help = 'Version of script', version='%(prog)s {}'.format (version))
    parent_group.add_argument ('--database', '-d', type=str, default=1, help = 'The name of the database file in n3 format',
            metavar = 'DBPATH')

    subparsers = parser.add_subparsers (dest = 'command', title = 'Commands',
		description = 'Commands that have to be placed in the first place of %(prog)s')

# 
    all_parser = subparsers.add_parser ('all', add_help = False, help = 'Execut all commands',
		description = ''' Perform excution of all internal commands  ''')

#    all_group = all_parser.add_argument_group (title='Options')
#    all_group.add_argument ('--help', '-h', action='help', help='Help')

    all_parser = subparsers.add_parser ('diag', add_help = False, help = 'Diagram of the connections',
		description = ''' Draw structure and connections of programs and servers  ''')

    all_parser = subparsers.add_parser ('rules', add_help = False, help = 'Rules',
		description = ''' Generate rules based on internal structure ''')

    all_parser = subparsers.add_parser ('plan', add_help = False, help = 'IP plan',
		description = ''' Generate sheet with IP plan  ''')

    all_parser = subparsers.add_parser ('conn', add_help = False, help = 'Connections',
		description = ''' Generate sheet with connections  ''')

    all_parser = subparsers.add_parser ('place', add_help = False, help = 'Placement of devices',
		description = ''' Generate sheet with placement of devices  ''')


    return parser

def parse(dot_base):
    p = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
    o = URIRef(prefix+"/Subnet")

    for net in g.triples((None,p,o)):
	# get name of subnet
	s = URIRef(net[0])
	p = URIRef(prefix+"/name")
	for name in g.triples((s,p,None)):
	    net_name=name[2]
	print "----"+net_name+"------";
	dot_subnet = dot_base.subgraph(name="cluster"+net_name, style='dotted', color='black', label=net_name, overlap='false');
	#  get list of servers
	s = URIRef(net[0])
	p = URIRef(prefix+"/hasServer")
	for server in g.triples((s,p,None)):
	    #	get name of server
	    s = URIRef(server[2])
	    p = URIRef(prefix+"/name")
	    for sname in g.triples((s,p,None)):
		server_name=sname[2]
	    #	get NetDev
	    s = URIRef(server[2])
	    p = URIRef(prefix+"/hasDevice")
	    server_ip2=[]
	    for ndev in g.triples((s,p,None)):
		#	get IP of server
		#fix me. Server can have multiple IP<->MAC links
		s = URIRef(ndev[2])
		p = URIRef(prefix+"/ip")
		for sip in g.triples((s,p,None)):
		    server_ip2.append(sip[2])

		s = URIRef(ndev[2])
		p = URIRef(prefix+"/hwAddr")
		for smac in g.triples((s,p,None)):
		    server_mac=smac[2]
	    #get replicas
	    p = URIRef(prefix+"/replica")
	    o = URIRef(server[2])
	    for replicas in g.triples((None,p,o)):
		s = URIRef(replicas[0])
		p = URIRef(prefix+"/hasDevice")
		for ndev in g.triples((s,p,None)):
		    #	get IP of server
		    #fix me. Server can have multiple IP<->MAC links
		    s = URIRef(ndev[2])
		    p = URIRef(prefix+"/ip")
		    #get IPs of replicas
		    for rip in g.triples((s,p,None)):
			server_ip2.append(rip[2])

		s = URIRef(replicas[0])
		p = URIRef(prefix+"/ip")
		#get IPs
		for rip in g.triples((s,p,None)):
		    server_ip2.append(rip[2])

	    server_ip='['+'],['.join(server_ip2)+']'

	    print "\t"+server_name+":"+server_ip

	    dot_server = dot_subnet.subgraph(name="cluster"+server_name, style='dotted', color='blue', label=server_name+":"+server_ip, overlap='false');
	    #get programs
	    s = URIRef(server[2])
	    p = URIRef(prefix+"/hasProgram")
	    for program in g.triples((s,p,None)):
		#get name of a program
		s = URIRef(program[2])
		p = URIRef(prefix+"/name")
		for pname in g.triples((s,p,None)):
		    program_name=pname[2]
		#get listenport of a program
		s = URIRef(program[2])
		p = URIRef(prefix+"/listenPort")
		program_port=""
		for listen in g.triples((s,p,None)):
		    program_port=listen[2]
		print "\t\t"+program_name+":"+program_port;
		dot_server.add_node(program_name, shape="record", name=program_name, label=program_name+":"+program_port, overlap='false');
		#get connection
		s = URIRef(program[2])
		p = URIRef(prefix+"/communicateWith")
		program_port=""
		for communicate in g.triples((s,p,None)):
		    #	get name of a program communicte with
		    s = URIRef(communicate[2])
		    p = URIRef(prefix+"/name")
		    for rpname in g.triples((s,p,None)):
			#remote port
			s = URIRef(rpname[0])
			p = URIRef(prefix+"/listenPort")
			for rportname in g.triples((s,p,None)):
			    remote_port=rportname[2]
			# dst server
			o = URIRef(rpname[0])
			p = URIRef(prefix+"/hasProgram")
			for rem_servers in g.triples((None,p,o)):
			    remote_server=rem_servers[0]

			#dst net device
			s = URIRef(remote_server)
			p = URIRef(prefix+"/hasDevice")
			remote_ip2=[]
			for ndev in g.triples((s,p,None)):
			    #get IP of server
			    s = URIRef(ndev[2])
			    p = URIRef(prefix+"/ip")
			    for res in g.triples((s,p,None)):
				remote_ip2.append(res[2])

			#get replicas
			p = URIRef(prefix+"/replica")
			o = URIRef(remote_server)
			for rreplicas in g.triples((None,p,o)):
			    s = URIRef(rreplicas[0])
			    p = URIRef(prefix+"/hasDevice")
			    for ndev in g.triples((s,p,None)):
				#get IP of server
				#fix me. Server can have multiple IP<->MAC links
				s = URIRef(ndev[2])
				p = URIRef(prefix+"/ip")
				#get IPs of replicas
				for drip in g.triples((s,p,None)):
	    			    remote_ip2.append(drip[2])

			    s = URIRef(rreplicas[0])
			    p = URIRef(prefix+"/ip")
			    for drip in g.triples((s,p,None)):
	    			remote_ip2.append(drip[2])

			remote_ip='['+'],['.join(remote_ip2)+']'
			#save results
			dst_prog.append(rpname[2])
			src_prog.append(program_name)
			dst_port.append(remote_port)
			src_ip.append(server_ip)
			src_hwAddr.append(server_mac)
			dst_ip.append(remote_ip)
    return

def run_diagram(namespace):
    fn_short=namespace.database[:-4]

    dot_base = ppp.AGraph(directed=False, name='Network', node_attr={'shape': 'record'}, overlap='false',strict=False,rankdir='LR')

    parse(dot_base)

    for i in range (0, len(src_prog)):
	dot_base.add_edge(src_prog[i], dst_prog[i])
	print src_prog[i]+":"+" -> "+dst_prog[i]+":"+dst_port[i]

    print "--------  links --------"
    print "SRC_IP -> DST_IP:DST_PORT"
    for i in range (0, len(src_prog)):
	print src_ip[i]+":"+" -> "+dst_ip[i]+":"+dst_port[i]

    dot_base.draw("output/"+fn_short+'.png',format='png',prog='dot')
    dot_base.draw("output/"+fn_short+'.dot',format='dot',prog='dot')

    return

def run_rules(namespace):
    fn_short=namespace.database[:-4]
    dot_base = ppp.AGraph(directed=False, name='Network', node_attr={'shape': 'record'}, overlap='false',strict=False,rankdir='LR')
    global sid
    if len(src_prog)==0:
	parse(dot_base)

    for i in range (0, len(src_ip)):
	add_src_dst_port(src_ip[i], src_hwAddr[i], 0, dst_ip[i], dst_port[i])
	add_src_dst(src_ip[i], dst_ip[i])

    f = open("output/"+fn_short+'.rules', 'w+')
    m = open("output/sid-msg.map", 'w+')

    print "-------- output --------" 
    f.write("#---output---\n");
    for i in range (0, len(u_src_ip)):
    #    print "alert tcp ["+u_src_ip[i]+"] any -> ["+u_dst_ip[i]+"] !["+u_dst_port[i]+"]"+ " (msg:\" Wrong port connection\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)";
	f.write("alert tcp ["+u_src_ip[i]+"] any -> ["+u_dst_ip[i]+"] !["+u_dst_port[i]+"]"+ " (msg:\" Wrong port connection\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)\n");
	m.write(str(sid)+"|| Wrong port connection\n");
	sid+=1

    print "-------- overall --------" 
    f.write("#---overall---\n");
    for i in range (0, len(ret_src_ip)):
    #    print "alert tcp ["+ret_src_ip[i]+"] any -> !["+ret_dst_ip[i]+"] any"+ " (msg:\" Attempt to connect to wrong IP\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)";
	f.write("alert tcp ["+ret_src_ip[i]+"] any -> !["+ret_dst_ip[i]+"] any"+ " (msg:\" Outgoing connections to illegal IPs\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)\n");
	m.write(str(sid)+"|| Outgoing connection to illegal IP\n");
	sid+=1
    #    print "alert tcp !["+ret_dst_ip[i]+"] any -> ["+ret_src_ip[i]+"] any"+ " (msg:\" Attempt to connect to wrong IP\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)";
	f.write("alert tcp !["+ret_dst_ip[i]+"] any -> ["+ret_src_ip[i]+"] any"+ " (msg:\" Incomming connections from illegal IPs \"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)\n");
	m.write(str(sid)+"|| Incomming connection from illegal IPs\n");
	sid+=1

    print "-------- hw_addr --------" 
    f.write("#---hw_addr---\n");

    p = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
    o = URIRef(prefix+"/NetDev")
    for ndev in g.triples((None,p,o)):
	s = URIRef(ndev[0])
	p = URIRef(prefix+"/ip")
	for nip in g.triples((s,p,None)):
	    tmp_ip=nip[2]

	s = URIRef(ndev[0])
	p = URIRef(prefix+"/hwAddr")
	for nhw in g.triples((s,p,None)):
	    tmp_hw=nhw[2]

	f.write("alert ip ["+tmp_ip+"] any -> any any " + " (msg:\" Wrong hw addr\"; eth_src:"+tmp_hw+";rev:1; sid:"+str(sid)+";)\n");
	m.write(str(sid)+"|| Wrong hw addr\n");
	sid+=1


    return

def run_plan(namespace):

    fn_short=namespace.database[:-4]

    workbook = xlsxwriter.Workbook("output/"+fn_short+'_ip-plan'+'.xlsx')

    sheet_ip = workbook.add_worksheet("IP plan")
    merge_format = workbook.add_format({
	'bold': 1,
	'border': 1,
	'align': 'center',
	'valign': 'vcenter'})

    sheet_ip.merge_range('A1:D1', 'IP plan', merge_format)

    ip_plan=[]
    ip_plan.append(['IP Address','Hostname', 'Description']);

    p = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
    o = URIRef(prefix+"/Server")
    for server in g.triples((None,p,o)):
	t_name=''
	t_ip=''
	t_desc=''
	s = URIRef(server[0])
	p = URIRef(prefix+"/name")
	for name in g.triples((s,p,None)):
		t_name=name[2]

	s = URIRef(server[0])
	p = URIRef(prefix+"/hasDevice")
	for ndev in g.triples((s,p,None)):
	    #get IP of server
	    s = URIRef(ndev[2])
	    p = URIRef(prefix+"/ip")
	    for ip in g.triples((s,p,None)):
		#only one IP per server now
		t_ip=ip[2]

	#fixme, turn t_ip into list
	s = URIRef(server[0])
	p = URIRef(prefix+"/ip")
	for ip in g.triples((s,p,None)):
		t_ip=ip[2]


	s = URIRef(server[0])
	p = URIRef(prefix+"/description")
	for desc in g.triples((s,p,None)):
	    t_desc=desc[2]

	ip_plan.append([t_name,t_ip,t_desc])

    row = 2
    col = 0

    for line in ip_plan:
	sheet_ip.write(row, col, line[0])
	sheet_ip.write(row, col+1, line[1])
	sheet_ip.write(row, col+2, line[2])
	row += 1

    workbook.close()

    return 

def run_connectivity(namespace):

    fn_short=namespace.database[:-4]

    workbook = xlsxwriter.Workbook("output/"+fn_short+'_phys'+'.xlsx')
    merge_format = workbook.add_format({
	'bold': 1,
	'border': 1,
	'align': 'center',
	'valign': 'vcenter'})

    sheet_connect = workbook.add_worksheet("Physical+L2 connectivity LAN")
    sheet_connect.merge_range('A1:D1', "Physical+L2 connectivity LAN", merge_format)

    connect=[]
    connect.append(['Source host',	'Port',	'Port type',	'VLAN',	'Switch', 'Port']);

    #servers
    p = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
    o = URIRef(prefix+"/Server")
    for server in g.triples((None,p,o)):
	tmp=[]
	#name
	s = URIRef(server[0])
	p = URIRef(prefix+"/name")
	for name in g.triples((s,p,None)):
	    tmp.append(name[2])

	s = URIRef(server[0])
	p = URIRef(prefix+"/hasDevice")
	#replica without devices
	if len(list(g.triples((s,p,None)))) ==0:
		tmp.append("n/d")
		tmp.append("n/d")
		tmp.append("n/d")
		tmp.append("n/d")
		tmp.append("n/d")
		tmp.append("n/d")
	for ndev in g.triples((s,p,None)):
	    #get IP of server
	    s = URIRef(ndev[2])
	    p = URIRef(prefix+"/name")
	    for name in g.triples((s,p,None)):
		tmp.append(name[2]);

	    s = URIRef(ndev[2])
	    p = URIRef(prefix+"/type")
	    for ndtype in g.triples((s,p,None)):
		ntype=ndtype[2];

	    s = URIRef(ndev[2])
	    p = URIRef(prefix+"/speed")
	    for ndspeed in g.triples((s,p,None)):
		nspeed=ndspeed[2];

	    tmp.append(nspeed+"-"+ntype)
	    tmp.append("0");
	    #port id
	    p = URIRef(prefix+"/connectedWith")
	    o = URIRef(ndev[2])
	    for port in g.triples((None,p,o)):
		p = URIRef(prefix+"/port")
		o = URIRef(port[0])
		#switch
		for switch in g.triples((None,p,o)):
		    #switch name
		    s = URIRef(switch[0])
		    p = URIRef(prefix+"/name")
		    for s_name in g.triples((s,p,None)):
			tmp.append(s_name[2])
		#port number
		s = URIRef(port[0])
		p = URIRef(prefix+"/number")
		for number in g.triples((s,p,None)):
		    tmp.append(number[2])

	connect.append(tmp)

    row = 2
    col = 0

    for line in connect:
	sheet_connect.write(row, col,   line[0])
	sheet_connect.write(row, col+1, line[1])
	sheet_connect.write(row, col+2, line[2])
	sheet_connect.write(row, col+3, line[3])
	sheet_connect.write(row, col+4, line[4])
	sheet_connect.write(row, col+5, line[5])
	row += 1

    workbook.close()
    return

def run_placement(namespace):

    fn_short=namespace.database[:-4]

    workbook = xlsxwriter.Workbook("output/"+fn_short+'_place'+'.xlsx')
    merge_format = workbook.add_format({
	'bold': 1,
	'border': 1,
	'align': 'center',
	'valign': 'vcenter'})

    sheet_dc = workbook.add_worksheet("Physical placement")
    sheet_dc.merge_range('A1:D1', "Physical placement", merge_format)

    phys=[]
    phys.append(['Equipment','Rack','Unit','Power, W','Size, units','Weight, kg','Cooling, BTU/hr']);

    p = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
    o = URIRef(prefix+"/Server")
    for server in g.triples((None,p,o)):
	tmp=[]
	#name
	s = URIRef(server[0])
	p = URIRef(prefix+"/name")
	for name in g.triples((s,p,None)):
	    tmp.append(name[2])
	#unit
	p = URIRef(prefix+"/occupiedBy")
	o = URIRef(server[0])
	#replicat without placement
	if len(list(g.triples((None,p,o)))) ==0:
		tmp.append("n/d")
		tmp.append("n/d")
	for unit in g.triples((None,p,o)):
	    #rack id
	    p = URIRef(prefix+"/hasUnit")
	    o = URIRef(unit[0])
	    for racks in g.triples((None,p,o)):
		#rack name
		s = URIRef(racks[0])
		p = URIRef(prefix+"/name")
		for r_name in g.triples((s,p,None)):
		    tmp.append(r_name[2])
	    #unit name
	    s = URIRef(unit[0])
	    p = URIRef(prefix+"/number")
	    for u_number in g.triples((s,p,None)):
		tmp.append(u_number[2])

	#model id
	s = URIRef(server[0])
	p = URIRef(prefix+"/model")
	#replica without model
	if len(list(g.triples((s,p,None)))) ==0:
		tmp.append("n/d")
		tmp.append("n/d")
		tmp.append("n/d")
		tmp.append("n/d")
	for models in g.triples((s,p,None)):
	    #model features
	    s = URIRef(models[2])
	    p = URIRef(prefix+"/power")
	    for power in g.triples((s,p,None)):
		tmp.append(power[2])

	    s = URIRef(models[2])
	    p = URIRef(prefix+"/size")
	    for size in g.triples((s,p,None)):
		tmp.append(size[2])

	    s = URIRef(models[2])
	    p = URIRef(prefix+"/weight")
	    for weight in g.triples((s,p,None)):
		tmp.append(weight[2])

	    s = URIRef(models[2])
	    p = URIRef(prefix+"/cooling")
	    for cooling in g.triples((s,p,None)):
		tmp.append(cooling[2])

	phys.append(tmp)

    #switches
    p = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
    o = URIRef(prefix+"/Switch")
    for switch in g.triples((None,p,o)):
	tmp=[]
	#name
	s = URIRef(switch[0])
	p = URIRef(prefix+"/name")
	for name in g.triples((s,p,None)):
	    tmp.append(name[2])
	#unit
	p = URIRef(prefix+"/occupiedBy")
	o = URIRef(switch[0])
	for unit in g.triples((None,p,o)):
	#rack id
	    p = URIRef(prefix+"/hasUnit")
	    o = URIRef(unit[0])
	    for racks in g.triples((None,p,o)):
	    #rack name
		s = URIRef(racks[0])
		p = URIRef(prefix+"/name")
		for r_name in g.triples((s,p,None)):
		    tmp.append(r_name[2])
	    #unit name
	    s = URIRef(unit[0])
	    p = URIRef(prefix+"/number")
	    for u_number in g.triples((s,p,None)):
		tmp.append(u_number[2])

	#model id
	s = URIRef(switch[0])
	p = URIRef(prefix+"/model")
	for models in g.triples((s,p,None)):
	    #model features
	    s = URIRef(models[2])
	    p = URIRef(prefix+"/power")
	    for power in g.triples((s,p,None)):
		tmp.append(power[2])

	    s = URIRef(models[2])
	    p = URIRef(prefix+"/size")
	    for size in g.triples((s,p,None)):
		tmp.append(size[2])

	    s = URIRef(models[2])
	    p = URIRef(prefix+"/weight")
	    for weight in g.triples((s,p,None)):
		tmp.append(weight[2])

	    s = URIRef(models[2])
	    p = URIRef(prefix+"/cooling")
	    for cooling in g.triples((s,p,None)):
		tmp.append(cooling[2])

    phys.append(tmp)

    row = 2
    col = 0

    for line in phys:
	sheet_dc.write(row, col, line[0])
	sheet_dc.write(row, col+1, line[1])
	sheet_dc.write(row, col+2, line[2])
	sheet_dc.write(row, col+3, line[3])
	sheet_dc.write(row, col+4, line[4])
	sheet_dc.write(row, col+5, line[5])
	sheet_dc.write(row, col+6, line[6])
	row += 1

    workbook.close()

    return

if __name__ == '__main__':
    parser = createParser()
    namespace = parser.parse_args(sys.argv[1:])

    prefix="file://"+os.getcwd()
    g.parse(namespace.database)

    if not os.path.exists("output"):
	os.makedirs("output")

    if namespace.command == "all":
	run_diagram(namespace)
	run_rules(namespace)
	run_plan(namespace)
	run_connectivity(namespace)
	run_placement(namespace)
    elif namespace.command == "diag":
	run_diagram (namespace)
    elif namespace.command == "rules":
	run_rules (namespace)
    elif namespace.command == "plan":
	run_plan (namespace)
    elif namespace.command == "conn":
	run_connectivity (namespace)
    elif namespace.command == "place":
	run_placement (namespace)
    else:
	parser.print_help()
