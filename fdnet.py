#!/usr/bin/python

import sys
from rdflib.graph import Graph
from rdflib import URIRef, Literal, BNode, Namespace
from rdflib import RDF
from graphviz import Digraph
import pygraphviz as ppp
import os

if len(sys.argv) < 2:
    print "Please provide network structure in RDF format. Example: fdnet.py text.rdf"
    sys.exit()
else:
    fname=sys.argv[1]
    fn_short=fname[:-4]

print fname
g = Graph()

#g.parse("uraf.n3", format="n3")
g.parse(fname)

#for triple in g.triples((None, None, None)):
#    print triple

#
#global variables
#

prefix="file://"+os.getcwd()

nets=[]

src_ip=[]
dst_ip=[]
src_port=[]
dst_port=[]
src_prog=[]
dst_prog=[]

#
#
#
p = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
o = URIRef(prefix+"/Subnet")

print o

for triple in g.triples((None,p,o)):
    nets.append(triple)

dot_base = ppp.AGraph(directed=False, name='Network', node_attr={'shape': 'record'}, overlap='false',strict=False,rankdir='LR')


p = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
o = URIRef(prefix+"/Subnet")

for net in g.triples((None,p,o)):
# get name of subne
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
#	print (server[0], server[1], server[2])
#	get name of server
	s = URIRef(server[2])
	p = URIRef(prefix+"/name")
	for sname in g.triples((s,p,None)):
	    server_name=sname[2]
#	get IP of server
	s = URIRef(server[2])
	p = URIRef(prefix+"/ip")
	for sip in g.triples((s,p,None)):
	    server_ip=sip[2]
	print "\t"+server_name+":"+server_ip
	dot_server = dot_subnet.subgraph(name="cluster"+server_name, style='dotted', color='blue', label=server_name+":"+server_ip, overlap='false');
#	dot.add_node(server_name);
#get programs
	s = URIRef(server[2])
	p = URIRef(prefix+"/hasProgram")
	for program in g.triples((s,p,None)):
#	get name of a program
	    s = URIRef(program[2])
	    p = URIRef(prefix+"/name")
	    for pname in g.triples((s,p,None)):
		program_name=pname[2]
#	get listenport of a program
	    s = URIRef(program[2])
	    p = URIRef(prefix+"/listenPort")
	    program_port=""
	    for listen in g.triples((s,p,None)):
		program_port=listen[2]
	    print "\t\t"+program_name+":"+program_port;
	    dot_server.add_node(program_name, shape="record", name=program_name, label=program_name+":"+program_port, overlap='false');
#	get connection
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
# dst ip
		    s = URIRef(remote_server)
		    p = URIRef(prefix+"/ip")
		    for res in g.triples((s,p,None)):
			remote_ip=res[2]
#save results
		    dst_prog.append(rpname[2])
		    src_prog.append(program_name)
		    dst_port.append(remote_port)
		    src_ip.append(server_ip)
		    dst_ip.append(remote_ip)


print "-------- Connections--------" 
for i in range (0, len(src_prog)):
    dot_base.add_edge(src_prog[i], dst_prog[i])
    print src_prog[i]+":"+" -> "+dst_prog[i]+":"+dst_port[i]

print "--------  links --------"
print "SRC_IP -> DST_IP:DST_PORT"
for i in range (0, len(src_prog)):
    print src_ip[i]+":"+" -> "+dst_ip[i]+":"+dst_port[i]


print "-------- Suricata rules --------" 
#output
u_src_prog=[]
u_dst_prog=[]
u_dst_ip=[]
u_dst_port=[]
u_src_ip=[]

#overall
ret_src_ip=[]
ret_dst_ip=[]

#input
in_src_ip=[]
in_dst_ip=[]


#
def add_dst_src(s_ip, d_ip):
    global in_src_ip;
    global in_dst_ip;
#    print (s_ip, d_ip)
    for i in range (0, len(in_dst_ip)):
	if in_dst_ip[i]==d_ip and s_ip in in_src_ip[i]:
	    return;
	elif in_dst_ip[i]==d_ip:
	    in_src_ip[i]=in_src_ip[i]+", "+s_ip;
	    return;
    in_dst_ip.append(d_ip)
    in_src_ip.append(s_ip)


def add_src_dst(s_ip, d_ip):
    global ret_src_ip;
    global ret_dst_ip;
#    print (s_ip, d_ip)
    for i in range (0, len(ret_src_ip)):
	if ret_src_ip[i]==s_ip and d_ip in ret_dst_ip[i]:
	    return;
	elif ret_src_ip[i]==s_ip:
	    ret_dst_ip[i]=ret_dst_ip[i]+", "+d_ip;
	    return;
    ret_src_ip.append(s_ip)
    ret_dst_ip.append(d_ip)


def add_src_dst_port(s_ip, s_port, d_ip, d_port):
    global u_src_ip;
    global u_dst_ip;
    global u_src_port;
    global u_dst_port;
    for i in range (0, len(u_src_ip)):
	if u_src_ip[i]==s_ip and u_dst_ip[i]==d_ip:
	    u_dst_port[i]=u_dst_port[i]+", "+d_port;
	    return;
    u_src_ip.append(s_ip)
    u_dst_ip.append(d_ip)
    u_dst_port.append(d_port)
	

for i in range (0, len(src_ip)):
	add_src_dst_port(src_ip[i], 0, dst_ip[i], dst_port[i])
	add_src_dst(src_ip[i], dst_ip[i])

for i in range (0, len(src_ip)):
	add_src_dst(src_ip[i], dst_ip[i])

for i in range (0, len(src_ip)):
	add_src_dst(src_ip[i], dst_ip[i])

for i in range (0, len(src_ip)):
	add_dst_src(src_ip[i], dst_ip[i])

if not os.path.exists("output"):
    os.makedirs("output")

sid=6000000

f = open("output/"+fn_short+'.rules', 'w+')
s = open("output/sid-msg.map", 'w+')

print "-------- output --------" 
f.write("---output---\n");
for i in range (0, len(u_src_ip)):
#    print "alert tcp ["+u_src_ip[i]+"] any -> ["+u_dst_ip[i]+"] !["+u_dst_port[i]+"]"+ " (msg:\" Wrong port connection\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)";
    f.write("alert tcp ["+u_src_ip[i]+"] any -> ["+u_dst_ip[i]+"] !["+u_dst_port[i]+"]"+ " (msg:\" Wrong port connection\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)\n");
    s.write(str(sid)+"|| Wrong port connection\n");
    sid+=1

print "-------- input --------" 
f.write("---input---\n");
for i in range (0, len(in_dst_ip)):
#    print "alert tcp !["+in_src_ip[i]+"] any -> ["+in_dst_ip[i]+"] any"+ " (msg:\" Attempt to connect to wrong IP\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)";
    f.write("alert tcp !["+in_src_ip[i]+"] any -> ["+in_dst_ip[i]+"] any"+ " (msg:\" Incomming connection from illegal IP\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)\n");
    s.write(str(sid)+"|| Incomming connection from illegal IP\n");
    sid+=1

print "-------- overall --------" 
f.write("---overall---\n");
for i in range (0, len(ret_src_ip)):
#    print "alert tcp ["+ret_src_ip[i]+"] any -> !["+ret_dst_ip[i]+"] any"+ " (msg:\" Attempt to connect to wrong IP\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)";
    f.write("alert tcp ["+ret_src_ip[i]+"] any -> !["+ret_dst_ip[i]+"] any"+ " (msg:\" Outgoing connections to illegal IPs\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)\n");
    s.write(str(sid)+"|| Outgoing connection to illegal IP\n");
    sid+=1
#    print "alert tcp !["+ret_dst_ip[i]+"] any -> ["+ret_src_ip[i]+"] any"+ " (msg:\" Attempt to connect to wrong IP\"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)";
    f.write("alert tcp !["+ret_dst_ip[i]+"] any -> ["+ret_src_ip[i]+"] any"+ " (msg:\" Incomming connections from illegal IPs \"; rev:1; classtype:tcp-connection; sid:"+str(sid)+";)\n");
    s.write(str(sid)+"|| Incomming connection from illegal IPs\n");
    sid+=1

dot_base.draw("output/"+fn_short+'.png',format='png',prog='dot')
dot_base.draw("output/"+fn_short+'.dot',format='dot',prog='dot')
