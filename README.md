Python nRF52 DFU Server
============================

A python script for bluez gatttool using pexpect to achive Device Firmware Updates (DFU) to the nRF52.  
The host system is assumed to be some flavor of Linux.

**NOTE:**   
This is probably not a beginner's project.  
Peripheral firmware updating is a complex process, requiring several critical development support steps, not covered here, before the *dfu.py* utility can be used.

It is assumed that your peripheral firmware has been build to Nordic's SDK11.x + SoftDevice 11.x  
The target peripheral firmware should also include some variation of Nordic's DFU support.

How you get the target periheral to enter DFU-mode (e.g. advertizing *DfuTarg*) is not handled here.    
It is assumed you can trigger your peripheral to enter the bootloader; either by a hardware switch or application-trigger.

The *dfu.py* utility comes into play only if the peripheral has the DFU Service working.

System:
* Ubuntu 14.04
* Asus X550LD (With integrated Bluetooth 4.0 interface)
* bluez - 5.34 or later (type "bluetoothd -v" to check your bluez version)

This project assumes you are developing on a Linux/Unix or OSX system and deploying to a Linux system. 

Prerequisite
------------

    sudo pip install pexpect
    sudo pip install intelhex

Firmware Build Requirement
--------------------------
* Your nRF52 firmware build method will produce either a firmware hex or bin file named *application.hex* or *application.bin*.  This naming convention is per Nordics DFU specification, which is use by this DFU server as well as the Android Master Control Panel DFU, and iOS DFU app.  
* Your nRF52 firmware build method will produce an Init file (aka *application.dat*).  Again, this is per Nordic's naming conventions. 

The *nrfutil* Utility
---------------------
https://github.com/NordicSemiconductor/pc-nrfutil/tree/0_5_1

The nrfutil utility will read your build method's hex file and produce a zip file. Ideally, you would incorporate the nrfutil utility into your build system so that your build method will generate the dat file for each build.  

nrfutil dfu genpkg app_package.zip --application application.hex

Usage
-----
There are two ways to speicify firmware files for this OTA-DFU server. Either by specifying both the <hex or bin> file with the dat file, or more easily by the zip file, which contains both the hex and dat files.  
The new "zip file" form is encouraged by Nordic, but the older hex+dat file methods should still work.  


Usage Examples
--------------

    > sudo ./dfu.py -f ~/application.hex -d ~/application.dat -a EF:FF:D2:92:9C:2A

or

    > sudo ./dfu.py -z ~/application.zip -a EF:FF:D2:92:9C:2A  

To figure out the address of DfuTarg do a 'hcitool lescan' - 

    $ sudo hcitool -i hci0 lescan  
    LE Scan ...   
    CD:E3:4A:47:1C:E4 DfuTarg  
    CD:E3:4A:47:1C:E4 (unknown) 


Example of *dfu.py* Output
------------------------

    ~/src/ota-dfu/ $ sudo ./dfu.py -z application_debug_1435008894.zip -a EF:FF:D2:92:9C:2A
    DFU Server start
    unzip_dir: /tmp/application_debug_1435008894_nzjesh
    input_setup
    bin array size:  72352
    scan_and_connect
    dfu_send_image
    [0, 0, 0, 0, 0, 0, 0, 0, 160, 26, 1, 0]
    Sending hex file size
    oper: RESPONSE, proc: START, status: SUCCESS
    dfu_send_info
    PKT_RCPT:      200
    PKT_RCPT:      400
    PKT_RCPT:      600
    PKT_RCPT:      800
    PKT_RCPT:     1000
    PKT_RCPT:     1200
    PKT_RCPT:     1400
    PKT_RCPT:     1600
    PKT_RCPT:     1800
    PKT_RCPT:     2000
    PKT_RCPT:     2200
    PKT_RCPT:     2400
    PKT_RCPT:     2600
    PKT_RCPT:     2800
    PKT_RCPT:     3000
      ...
      ...
      ...
    PKT_RCPT:    69800
    PKT_RCPT:    70000
    PKT_RCPT:    70200
    PKT_RCPT:    70400
    PKT_RCPT:    70600
    PKT_RCPT:    70800
    PKT_RCPT:    71000
    PKT_RCPT:    71200
    PKT_RCPT:    71400
    PKT_RCPT:    71600
    PKT_RCPT:    71800
    PKT_RCPT:    72000
    PKT_RCPT:    72200
    State timeout
    DFU Server done

**NOTE:**  
The final "State timeout" is due to the target peripheral rebooting, as expected, and the disconnect not getting back soon enough.<br>
This is benign: the update should have been successful and the peripheral should have restarted and run the new firmware.<br>

<b>For Windows or Mac here other repos:</b><br>
Windows Application: https://github.com/astronomer80/nrf52_bledfu_win<br>
Mac application: https://github.com/astronomer80/nrf52_bledfu_mac<br>

***DFU Procedure performed by this script****<br>
1)Send 'START DFU' opcode + Application Command (0x0104)<br>
2)Send the image size<br>
3)Send 'INIT DFU' Command (0x0200): Called in the controlPoint_CalueChanged event invoked when the BLE device replies after sending the image size.<br>
4)Transmit the Init image (The file DAT content)<br>
5)Send 'INIT DFU' + Complete Command (0x0201)<br>
6)Send packet receipt notification interval (currently 10) (0x080000)<br>
7)Send 'RECEIVE FIRMWARE IMAGE' command to set DFU in firmware receive state. (0x0300)<br>
8)Send bin array contents as a series of packets (burst mode). Each segment is pkt_payload_size bytes long. For every packet send, wait for notification.<br>
9)Send Validate Command (0x0400)<br>
10)Send Activate and Reset Command (0x0500)<br>

**LINKS**  
https://infocenter.nordicsemi.com/topic/com.nordic.infocenter.sdk5.v11.0.0/bledfu_application.html<br>
https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk5.v11.0.0%2Fbledfu_transport_bleservice.html<br>
https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk5.v11.0.0%2Fbledfu_architecture_transfer.html<br>

**TODO**  
<<<<<<< HEAD
- Bluez installation automatically
- Add scan command
- Include nrfutil command
=======
- Go in DFU Mode buttonless: 
Check buttonless branch. TODO: Clean the code
>>>>>>> 6ea5d668def44647b1b9ca3cc95afb60863eaba3
- Send encrypted applications
- Speedup the procedure
- Add softdevice and bootloader update
