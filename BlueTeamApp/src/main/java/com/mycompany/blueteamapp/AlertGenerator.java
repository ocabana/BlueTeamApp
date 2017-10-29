/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.blueteamapp;

/**
 *
 * @author olyve
 */
import android.app.AlertDialog;
import android.app.Application;
import android.content.Context;
import android.content.DialogInterface;

public class AlertGenerator {
    public AlertGenerator(String IP, String info){
        //Taken from https://stackoverflow.com/questions/2115758/how-do-i-display-an-alert-dialog-on-android
        Context con  = new Application();
        AlertDialog.Builder builder1 = new AlertDialog.Builder(con);
        builder1.setMessage("An IP (" + IP + ") has attempted a malicious activity against this device. " + info);
        builder1.setCancelable(true);

        builder1.setPositiveButton(
            "OK",
            new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                    dialog.cancel();
                }
            });
        
        AlertDialog alert11 = builder1.create();
        alert11.show();
    }
}
