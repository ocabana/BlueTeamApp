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
    public int src_port, dst_port, ttl, window, size, ihl, offset, sequence, acknowledgement;
    public IpNumber protocol;  
    public boolean[] ip_flags;
    public boolean[] tcp_flags = null;
    public List<IpV4Option> options;
    public String tos, version, code, type, payload;
    public String[] returnFeatures(){
        String[] features = new String[20];
        features[0] = src_ip.getHostAddress();
        features[1] = dst_ip.getHostAddress();
        features[2] = src_port + "";
        features[3] = dst_port + "";
        features[4] = ttl + "";
        features[5] = window + "";
        features[6] = size + "";
        features[7] = ihl + "";
        features[8] = offset + "";
        features[9] = sequence + "";
        features[10] = acknowledgement + "";
        features[11] = protocol.valueAsString();
        features[12] = ip_flags.toString();
        features[13] = tcp_flags.toString();
        features[14] = options.toString();
        features[15] = tos;
        features[16] = version;
        features[17] = code;
        features[18] = type;
        features[19] = payload;
        return features;
    }    
}
