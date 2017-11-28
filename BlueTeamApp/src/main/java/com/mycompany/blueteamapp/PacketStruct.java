/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.blueteamapp;

import java.net.Inet4Address;
import java.sql.Timestamp;
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
    public Inet4Address src_ip = null, dst_ip = null;
    public int src_port = -1, dst_port = -1, ttl = -1, window = -1, size = -1, ihl = -1, offset = -1, sequence = -1, acknowledgement = -1;
    public IpNumber protocol = null;  
    public boolean[] ip_flags = null;
    public boolean[] tcp_flags = null;
    public List<IpV4Option> options = null;
    public Timestamp time = null;
    public String tos = "", version = "", code = "", type = "", payload = "";
    public String[] returnFeatures(){
        String trans_protocol = (protocol == null)? "" : protocol.valueAsString();
        if(trans_protocol.equals("1"))
            trans_protocol = "TCP";
        else if(trans_protocol.equals("17"))
            trans_protocol = "UDP";
        else
            trans_protocol = "ICMP";
        
        String[] features = new String[20];
        features[0] = (src_ip == null)? "" : src_ip.getHostAddress();
        features[1] = (dst_ip == null)? "" : dst_ip.getHostAddress();
        features[2] = (src_port == -1)? "" : src_port + "";
        features[3] = (dst_port == -1)? "" : dst_port + "";
        features[4] = (ttl == -1)? "" : ttl + "";
        features[5] = (window == -1)? "" : window + "";
        features[6] = (size == -1)? "" : size + "";
        features[7] = (ihl == -1)? "" : ihl + "";
        features[8] = (offset == -1)? "" : offset + "";
        features[9] = (sequence == -1)? "" : sequence + "";
        features[10] = (acknowledgement == -1)? "" : acknowledgement + "";
        features[11] = trans_protocol;
        features[12] = (ip_flags == null)? "" : ip_flags.toString();
        features[13] = (tcp_flags == null)? "" : tcp_flags.toString();
        features[14] = (options == null)? "" : options.toString();
        features[15] = tos;
        features[16] = version;
        features[17] = code;
        features[18] = type;
        features[19] = payload;
        return features;
    }    
}
