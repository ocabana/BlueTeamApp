package com.mycompany.blueteamapp;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.sql.Timestamp;

/**
 * Inspired from: A Network Activity Classification Schema and Its Application to Scan Detection
 * @author o_cabana
 */
public class TCPSession {
    public Timestamp lastpacket = new Timestamp(0L);
    ////////////////////////////syn,   ack,   fin,   urg,   psh,   rst    
    //public boolean[] flags = {false, false, false, false, false, false};
    public int state = -1;
    public int repeats = 0;
}

