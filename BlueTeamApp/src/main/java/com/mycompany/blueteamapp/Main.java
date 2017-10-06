/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.blueteamapp;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.util.NifSelector;

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
        
        packetInfo.size = p.getHeader().length();
        
        IpV4Packet ipp = p.get(IpV4Packet.class);
        
        packetInfo.src_ip = ipp.getHeader().getSrcAddr();
        packetInfo.dst_ip = ipp.getHeader().getDstAddr();
        packetInfo.ttl = ipp.getHeader().getTtlAsInt();
        
        packetInfo.protocol = ipp.getHeader().getProtocol().valueAsString();
        
        if(packetInfo.protocol.equals("TCP")){
            TcpPacket tp = ipp.get(TcpPacket.class);
            packetInfo.window = tp.getHeader().getWindowAsInt();
            
            packetInfo.src_port = tp.getHeader().getSrcPort().valueAsInt();
            packetInfo.dst_port = tp.getHeader().getDstPort().valueAsInt();
            
            
        }else if(packetInfo.protocol.equals("UDP")){
            UdpPacket up = ipp.get(UdpPacket.class);
            
            packetInfo.src_port = up.getHeader().getSrcPort().valueAsInt();
            packetInfo.dst_port = up.getHeader().getDstPort().valueAsInt();
            
        }else{
            //do something else
        }
        
        return packetInfo;
    }
}
