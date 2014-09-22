#!/usr/bin/python

import sys
from rdflib.graph import Graph
from rdflib import URIRef, Literal, BNode, Namespace
from rdflib import RDF
from graphviz import Digraph
import pygraphviz as ppp
import os

if len(sys.argv) < 2:
    print "Please provide network structure in RDF format. Example: fdnet.py text.RDF"
    sys.exit()
else:
    fname=sys.argv[1]

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

dot_base = ppp.AGraph(directed=True, name='Network', node_attr={'shape': 'record'})


p = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
o = URIRef(prefix+"/Subnet")

for net in g.triples((None,p,o)):
# get name of subne
    s = URIRef(net[0])
    p = URIRef(prefix+"/name")
    for name in g.triples((s,p,None)):
	net_name=name[2]
    print "----"+net_name+"------";
    dot_subnet = dot_base.subgraph(name="cluster"+net_name, style='dotted', color='black', label=net_name);
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
	dot_server = dot_subnet.subgraph(name="cluster"+server_name, style='dotted', color='blue', label=server_name+":"+server_ip);
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
	    dot_server.add_node(program_name, shape="record", name=program_name, label=program_name+":"+program_port);
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

print "-------- Snort Rules--------" 
for i in range (0, len(src_prog)):
    print "alert tcp "+src_ip[i]+" any -> "+dst_ip[i]+" !"+dst_port[i]+ " (msg:\" Attempt to connect to wrong IP\"; rev:1; classtype:tcp-connection; sid:6000001;)"
    print "alert tcp "+src_ip[i]+" any -> !"+dst_ip[i]+" "+dst_port[i]+ " (msg:\" Attempt to connect to wrong port\"; rev:1; classtype:tcp-connection; sid:6000002;)"

dot_base.draw(fname+'.png',format='png',prog='dot')
dot_base.draw(fname+'.dot',format='dot',prog='dot')
