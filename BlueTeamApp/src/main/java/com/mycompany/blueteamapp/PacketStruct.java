/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.blueteamapp;

import java.net.Inet4Address;
import java.util.List;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;

/**
 *
 * @author olyve
 */
public class PacketStruct {
    public Inet4Address src_ip, dst_ip;
    public short checksum;
    public int src_port, dst_port, ttl, window, size, id, ihl, offset, sequence, acknowledgement;
    public IpNumber protocol;  
    public boolean[] ipflags;
    public boolean[] tcpFlags = null;
    public List<IpV4Option> options;
    public IpV4Tos tos;
    public IpVersion version;
    public String code, type;
    
}
