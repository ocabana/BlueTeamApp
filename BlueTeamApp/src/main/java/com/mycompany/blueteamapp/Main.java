/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.blueteamapp;

import java.io.IOException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.Builder;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.IcmpV4Type;

/**
 *
 * @author olyve
 */
public class Main {
    public static void Main(String[] args) throws PcapNativeException, NotOpenException, IOException {
        //PcapNetworkInterface inter = new NifSelector().selectNetworkInterface();
        //PcapHandle nextPackets;       
        //Packet p;
    }
    static PacketStruct dissectPacket(Packet p){
        PacketStruct packetInfo = new PacketStruct();       
        IpV4Packet ipp = p.get(IpV4Packet.class);
        
        packetInfo.size = p.getHeader().length();
        packetInfo.src_ip = ipp.getHeader().getSrcAddr();
        packetInfo.dst_ip = ipp.getHeader().getDstAddr();
        packetInfo.ttl = ipp.getHeader().getTtlAsInt();
        
        packetInfo.protocol = ipp.getHeader().getProtocol();
        packetInfo.options = ipp.getHeader().getOptions();
        packetInfo.tos = ipp.getHeader().getTos().toString();
        packetInfo.version = ipp.getHeader().getVersion().valueAsString();
        packetInfo.ihl = ipp.getHeader().getIhlAsInt();
        
        packetInfo.ip_flags = new boolean[4];
        packetInfo.ip_flags[0] = ipp.getHeader().getDontFragmentFlag();
        packetInfo.ip_flags[1] = ipp.getHeader().getMoreFragmentFlag();
        packetInfo.ip_flags[2] = ipp.getHeader().getReservedFlag();
        packetInfo.ip_flags[3] = ipp.getHeader().hasValidChecksum(true);
        
        if(packetInfo.protocol.equals("1")){
            TcpPacket tp = ipp.get(TcpPacket.class);
            packetInfo.window = tp.getHeader().getWindowAsInt();
            
            packetInfo.src_port = tp.getHeader().getSrcPort().valueAsInt();
            packetInfo.dst_port = tp.getHeader().getDstPort().valueAsInt();
            
            packetInfo.tcp_flags = new boolean[6];
            packetInfo.tcp_flags[0] = tp.getHeader().getAck();
            packetInfo.tcp_flags[1] = tp.getHeader().getFin();
            packetInfo.tcp_flags[2] = tp.getHeader().getPsh();
            packetInfo.tcp_flags[3] = tp.getHeader().getRst();
            packetInfo.tcp_flags[4] = tp.getHeader().getSyn();
            packetInfo.tcp_flags[5] = tp.getHeader().getUrg();
            
            packetInfo.offset = tp.getHeader().getDataOffsetAsInt();
            packetInfo.acknowledgement = tp.getHeader().getAcknowledgmentNumber();
            packetInfo.sequence = tp.getHeader().getSequenceNumber();
                       
        }else if(packetInfo.protocol.equals("17")){
            UdpPacket up = ipp.get(UdpPacket.class);
            packetInfo.payload = up.getPayload().getRawData().toString();
            packetInfo.src_port = up.getHeader().getSrcPort().valueAsInt();
            packetInfo.dst_port = up.getHeader().getDstPort().valueAsInt();
            
        }else if(packetInfo.protocol.equals("4")){
            IcmpV4CommonPacket ic = ipp.get(IcmpV4CommonPacket.class);
            packetInfo.code = ic.getHeader().getCode().valueAsString();
            packetInfo.type = ic.getHeader().getType().valueAsString();
            if(ic.getHeader().getType().equals(IcmpV4Type.DESTINATION_UNREACHABLE)){
                UdpPacket up = ic.getPayload().get(UdpPacket.class);
                packetInfo.dst_port = up.getHeader().getSrcPort().valueAsInt();
                packetInfo.src_port = up.getHeader().getDstPort().valueAsInt();
            }
        }else{
            //do something else
        }
        
        return packetInfo;
    }
    static Packet returnPacket(PacketStruct ps){
        //Creates a Packet to return to the sender
        Packet p;
        Builder b = new Builder();
        b.protocol(ps.protocol);
        b.dstAddr(ps.src_ip);
        b.srcAddr(ps.dst_ip);
        b.getPayloadBuilder().build();
        IpV4Packet ip = b.build();
        
        return ip;
    }
    
    /*
    TCP, x, localhost, /system/bin/sh\x00\x00 /* Alerts: Shell Generation Attempt */
    //TCP, x, localhost, /^([[:space:]]*)\{([[:space:]]*)(.*)\"method\"([[:space:]]*):([[:space:]]*)\"(.*)\"/ /* Alerts: BCM. RPC request TCP */
    //TCP, x, localhost, /^([[:space:]]*)\{([[:space:]]*)(.*)\"method\"([[:space:]]*):([[:space:]]*)\"(.*)\"/ /* Alerts: BCM. RPC Request TCP Reverse*/
    //TCP, x, localhost, /^([[:space:]]*)\{([[:space:]]*)(.*)\"method\"([[:space:]]*):([[:space:]]*)\"(.*)\"/ /* Alerts: BCM. RPC Request HTTP */
    //TCP, localhost, x, /^([[:space:]]*)\{([[:space:]]*)\"(jsonrpc|result|error|id)\"([[:space:]]*):/ /*Alerts: BCM. RPC Response TCP*/
    //TCP, localhost, x, /^([[:space:]]*)\{([[:space:]]*)\"(jsonrpc|result|error|id)\"([[:space:]]*):/ /*Alerts: BCM. RPC Response TCP Reverse*/
    //TCP, localhost, x, /^([[:space:]]*)\{([[:space:]]*)\"(jsonrpc|result|error|id)\"([[:space:]]*):/ /*Alerts: BCM. RPC Response HTTP */
    /* Options: 
    * protocol = tcp|udp|icmp|icmp6|ip|ip6
    * srcip = IP address
    * dstip = IP address
    * payload = String (regex?)
    */
    
    static boolean compareSignature(String[] signature, PacketStruct p){
        String[] features = p.returnFeatures();
        if(features.length != signature.length){
            System.out.println("Problem with the signature format.");
            return false;
        }
        for(int i = 0; i < signature.length; i++){
             
        }
        return true;
    }
}
