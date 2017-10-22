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
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.Builder;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.IcmpV4Type;
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
        IpV4Packet ipp = p.get(IpV4Packet.class);
        
        packetInfo.size = p.getHeader().length();
        packetInfo.src_ip = ipp.getHeader().getSrcAddr();
        packetInfo.dst_ip = ipp.getHeader().getDstAddr();
        packetInfo.ttl = ipp.getHeader().getTtlAsInt();
        packetInfo.checksum = ipp.getHeader().getHeaderChecksum();
        packetInfo.id = ipp.getHeader().getIdentificationAsInt();
        
        packetInfo.protocol = ipp.getHeader().getProtocol();
        packetInfo.options = ipp.getHeader().getOptions();
        packetInfo.tos = ipp.getHeader().getTos();
        packetInfo.version = ipp.getHeader().getVersion();
        packetInfo.ihl = ipp.getHeader().getIhlAsInt();
        
        packetInfo.ipflags = new boolean[4];
        packetInfo.ipflags[0] = ipp.getHeader().getDontFragmentFlag();
        packetInfo.ipflags[1] = ipp.getHeader().getMoreFragmentFlag();
        packetInfo.ipflags[2] = ipp.getHeader().getReservedFlag();
        packetInfo.ipflags[3] = ipp.getHeader().hasValidChecksum(true);
        
        if(packetInfo.protocol.equals("TCP")){
            TcpPacket tp = ipp.get(TcpPacket.class);
            packetInfo.window = tp.getHeader().getWindowAsInt();
            
            packetInfo.src_port = tp.getHeader().getSrcPort().valueAsInt();
            packetInfo.dst_port = tp.getHeader().getDstPort().valueAsInt();
            
            packetInfo.tcpFlags = new boolean[6];
            packetInfo.tcpFlags[0] = tp.getHeader().getAck();
            packetInfo.tcpFlags[1] = tp.getHeader().getFin();
            packetInfo.tcpFlags[2] = tp.getHeader().getPsh();
            packetInfo.tcpFlags[3] = tp.getHeader().getRst();
            packetInfo.tcpFlags[4] = tp.getHeader().getSyn();
            packetInfo.tcpFlags[5] = tp.getHeader().getUrg();
            
            packetInfo.offset = tp.getHeader().getDataOffsetAsInt();
            packetInfo.acknowledgement = tp.getHeader().getAcknowledgmentNumber();
            packetInfo.sequence = tp.getHeader().getSequenceNumber();
                       
        }else if(packetInfo.protocol.equals("UDP")){
            UdpPacket up = ipp.get(UdpPacket.class);
            
            packetInfo.src_port = up.getHeader().getSrcPort().valueAsInt();
            packetInfo.dst_port = up.getHeader().getDstPort().valueAsInt();
            
        }else if(packetInfo.protocol.equals("ICMP")){
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
}
