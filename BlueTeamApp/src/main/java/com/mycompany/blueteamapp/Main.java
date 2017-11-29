/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.blueteamapp;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;
import javax.swing.JOptionPane;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
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
    static HashSet<String[]> signatures = new HashSet();
    static HashMap<InetAddress, TCPSession> sessions = new HashMap();
    static Timestamp bottomTime = new Timestamp(0);
    static float rateThreshold = 1;
    static int repeatThreshold = 10;
    static long timeThreshold = 120000;
    
    public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException, TimeoutException, InterruptedException {
        //PcapNetworkInterface inter = new NifSelector().selectNetworkInterface();
        PcapHandle nextPackets;       
        //Packet p;
        long time = System.currentTimeMillis();
        //The path to the .pcap file containing the packets
        File path = new File("pcapsample_00001_20171128102447");
        nextPackets = Pcaps.openOffline(path.listFiles()[0].getPath());
        
        //nextPackets = Pcaps.openOffline("", PcapHandle.TimestampPrecision.MICRO);
        generateSignature();
        while(1 == 1){
            //
            try{
                Packet p = nextPackets.getNextPacketEx();
                PacketStruct ps = dissectPacket(p);
                Iterator<String[]> it = signatures.iterator();
                while(it.hasNext())
                    compareSignature(it.next(), ps);

                if(ps.protocol.valueAsString().equals("1"))
                    AddSession(ps.src_ip, ps.tcp_flags, ps.time); 
                if(System.currentTimeMillis() - time > 60000){
                    clearOldSessions();
                    time = System.currentTimeMillis();
                }
            }catch(EOFException eof){
                System.out.println("No new packets");
                Thread.sleep(10000);
            }catch(Exception ex){
                System.out.println("Wrong packet format");
            }
        }
    }
    static PacketStruct dissectPacket(Packet p){
        PacketStruct packetInfo = new PacketStruct();       
        IpV4Packet ipp = p.get(IpV4Packet.class);
        //EthernetPacket ep = p.get(EthernetPacket.class);
        
        packetInfo.time = new Timestamp(System.currentTimeMillis());
        
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
            packetInfo.payload = tp.getPayload().getRawData().toString();
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
            if(signature[i].equals(""))
                continue;
            if(features[i].equals(""))
                return false;
            if(features[i].equals(signature[i]))
                generateAlert("Packet from " + features[0] + " is a perfect match for a signature.");
            else if(features[i].contains(signature[i]))
                generateAlert("Packet from " + features[0] + " has a partial match with a signature.");
            else if(features[i].matches(signature[i]))
                generateAlert("Packet from " + features[0] + " is a match for a signature.");
            return false;
        }
        return true;
    }
    static void generateSignature() throws FileNotFoundException{
        signatures = new HashSet();
        Scanner in = new Scanner(new FileInputStream("evencleanersignature.csv"));
        while(in.hasNext()){
            String input = in.nextLine();
            String[] frags = input.split(","), temp = {"","","","","","","","","","","","","","","","","","","",""};
            if(frags.length != 2)
                continue;
            temp[11] = frags[0];
            temp[19] = frags[1];
            signatures.add(temp);
        }
        in.close();
    }
    //Inspired from: A Network Activity Classification Schema and Its Application to Scan Detection
    static void AddSession(InetAddress addr, boolean[] flags, Timestamp time){
        if(flags.length != 6)
            return;
        if(sessions.containsKey(addr)){
            if(sessions.get(addr).state == 0){
                if(flags[0] && !flags[1] && !flags[2] && !flags[3] && !flags[4] && !flags[5]){
                    if(sessions.get(addr).repeats++ > repeatThreshold){
                        generateAlert("Repeated connection attempts from " + addr.getHostAddress());
                        sessions.remove(addr);
                    }else
                        sessions.get(addr).lastpacket = time;
                }else if(flags[1] && (flags[3] || flags[4]) && !flags[0] && !flags[2] && !flags[5]){
                    sessions.get(addr).repeats = 0;
                    sessions.get(addr).state = 2;
                    sessions.get(addr).lastpacket = time;
                }else{
                    generateAlert("Incomplete session with " + addr.getHostAddress());
                    sessions.remove(addr);
                }   
            }else if(sessions.get(addr).state == 1){
                if(flags[0] && !flags[2] && !flags[3] && !flags[4] && !flags[5]){
                    if(sessions.get(addr).repeats++ > repeatThreshold){
                        generateAlert("Repeated connection attempts from " + addr.getHostAddress());
                        sessions.remove(addr);
                    }else
                        sessions.get(addr).lastpacket = time;
                }else if((flags[5] && (flags[1] || flags[3] || flags[4]) && !flags[0] && !flags[2])
                        ||(flags[1] && flags[2] && (flags[3] || flags[4]) && !flags[0] && !flags[5])){
                    //Closed (To do: add code to treat repeats)
                    sessions.get(addr).repeats = 0;
                    sessions.get(addr).state = 3;
                    sessions.get(addr).lastpacket = time;
                }else{
                    generateAlert("Incomplete session with " + addr.getHostAddress());
                    sessions.remove(addr);
                }   
            }else if(sessions.get(addr).state == 2){
                if(flags[1] && (flags[3] || flags[4]) && !flags[0] && !flags[2] && !flags[5]){
                    if(sessions.get(addr).repeats++ > repeatThreshold){
                        generateAlert("Repeated connection attempts from " + addr.getHostAddress());
                        sessions.remove(addr);
                    }else
                        sessions.get(addr).lastpacket = time;
                }else if((flags[5] && (flags[1] || flags[3] || flags[4]) && !flags[0] && !flags[2])
                        ||(flags[1] && flags[2] && (flags[3] || flags[4]) && !flags[0] && !flags[5])){
                    //Closed (To do: add code to treat repeats)
                    sessions.get(addr).repeats = 0;
                    sessions.get(addr).state = 3;
                    sessions.get(addr).lastpacket = time;
                }else{
                    generateAlert("Incomplete session with " + addr.getHostAddress());
                    sessions.remove(addr);
                }   
            }else if(sessions.get(addr).state == 3){
                if(flags[0] && !flags[1] && !flags[2] && !flags[3] && !flags[4] && !flags[5]){
                    sessions.get(addr).repeats = 0;
                    sessions.get(addr).state = 0;
                    sessions.get(addr).lastpacket = time;
                    calculateTime(time);
                }else if((flags[5] && (flags[1] || flags[3] || flags[4]) && !flags[0] && !flags[2])
                    ||(flags[1] && flags[2] && (flags[3] || flags[4]) && !flags[0] && !flags[5])
                    ||(flags[1] && (flags[3] || flags[4]) && !flags[0] && !flags[2] && !flags[5])){
                    if(sessions.get(addr).repeats++ > repeatThreshold){
                        generateAlert("Repeated connection attempts from " + addr.getHostAddress());
                        sessions.remove(addr);
                    }else
                        sessions.get(addr).lastpacket = time;
                }
            }
        }else{
            if(flags[0] && !flags[1] && !flags[2] && !flags[3] && !flags[4] && !flags[5]){
                TCPSession session = new TCPSession();
                session.state = 0;
                session.lastpacket = time;
                calculateTime(time);
                sessions.put(addr, session);
            }else if(flags[0] && flags[1] && !flags[2] && !flags[3] && !flags[4] && !flags[5]){
                TCPSession session = new TCPSession();
                session.state = 1;
                session.lastpacket = time;
                calculateTime(time);
                sessions.put(addr, session);
            }else
                generateAlert("TCP packet with invalid/illegal flag combination from " + addr.getHostAddress());            
        }
    }
    static void calculateTime(Timestamp time){
        if(bottomTime.getTime() == 0)
            bottomTime = time;
        else if(bottomTime.compareTo(time) < 0){
            float rate = ((float)sessions.size()) / ((float)(time.getTime() - bottomTime.getTime()));
            if(rate > rateThreshold)
                generateAlert("Possible DDoS attack: SYN Flood");
        }else
            bottomTime = time;
    }
    static void generateAlert(String alertMessage){
        JOptionPane.showMessageDialog(null, alertMessage, "Security Warning", JOptionPane.WARNING_MESSAGE);
    }
    static void clearOldSessions(){
        //System.out.println(sessions.size());
        Iterator<Map.Entry<InetAddress, TCPSession>> it = sessions.entrySet().iterator();
        while(it.hasNext()){
            Map.Entry<InetAddress, TCPSession> e = it.next();
            if(System.currentTimeMillis() - e.getValue().lastpacket.getTime() > timeThreshold)
                it.remove();
        }
        //System.out.println(sessions.size());
        it = sessions.entrySet().iterator();
        long time = 0;
        while(it.hasNext()){
            Map.Entry<InetAddress, TCPSession> e = it.next();
            if(time == 0)
                time = e.getValue().lastpacket.getTime();
            else if(time > e.getValue().lastpacket.getTime())
                time = e.getValue().lastpacket.getTime();
        }
        bottomTime = new Timestamp(time);
    }
}
