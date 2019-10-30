#!/usr/bin/env python
#------------------------------------------------------------------------------
# DFU Server for Nordic nRF51 based systems.
# Conforms to nRF51_SDK 8.0 BLE_DFU requirements.
#------------------------------------------------------------------------------
import os
import sys
import pexpect
import optparse
import time

from intelhex import IntelHex
from array    import array
from unpacker import Unpacker
from tqdm import tqdm

debug = False

# DFU Opcodes
class Commands:
    START_DFU                    = 1
    INITIALIZE_DFU               = 2
    RECEIVE_FIRMWARE_IMAGE       = 3
    VALIDATE_FIRMWARE_IMAGE      = 4
    ACTIVATE_FIRMWARE_AND_RESET  = 5
    SYSTEM_RESET                 = 6
    PKT_RCPT_NOTIF_REQ           = 8

# DFU Procedures values
DFU_proc_to_str = {
    "01" : "START",
    "02" : "INIT",
    "03" : "RECEIVE_APP",
    "04" : "VALIDATE",
    "08" : "PKT_RCPT_REQ",
}

# DFU Operations values
DFU_oper_to_str = {
    "01" : "START_DFU",
    "02" : "RECEIVE_INIT",
    "03" : "RECEIVE_FW",
    "04" : "VALIDATE",
    "05" : "ACTIVATE_N_RESET",
    "06" : "SYS_RESET",
    "07" : "IMAGE_SIZE_REQ",
    "08" : "PKT_RCPT_REQ",
    "10" : "RESPONSE",
    "11" : "PKT_RCPT_NOTIF",
}

# DFU Status values
DFU_status_to_str = {
    "01" : "SUCCESS",
    "02" : "INVALID_STATE",
    "03" : "NOT_SUPPORTED",
    "04" : "DATA_SIZE",
    "05" : "CRC_ERROR",
    "06" : "OPER_FAILED",
}

def progress(count, total, suffix=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)

    sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', suffix))
    sys.stdout.flush()  # As suggested by Rom Ruben

#------------------------------------------------------------------------------
# Convert a number into an array of 4 bytes (LSB).
# This has been modified to prepend 8 zero bytes per the new DFU spec.
#------------------------------------------------------------------------------
def convert_uint32_to_array2(value):
    return [0,0,0,0,0,0,0,0,
           (value >> 0  & 0xFF),
           (value >> 8  & 0xFF),
           (value >> 16 & 0xFF),
           (value >> 24 & 0xFF)
    ]

def convert_uint32_to_array(value):
    return [
           (value >> 0  & 0xFF),
           (value >> 8  & 0xFF),
           (value >> 16 & 0xFF),
           (value >> 24 & 0xFF)
    ]


#------------------------------------------------------------------------------
# Convert a number into an array of 2 bytes (LSB).
#------------------------------------------------------------------------------
def convert_uint16_to_array(value):
    return [
        (value >> 0 & 0xFF),
        (value >> 8 & 0xFF)
    ]

#------------------------------------------------------------------------------
#
#------------------------------------------------------------------------------
def convert_array_to_hex_string(arr):
    hex_str = ""
    for val in arr:
        if val > 255:
            raise Exception("Value is greater than it is possible to represent with one byte")
        hex_str += "%02x" % val

    return hex_str

#------------------------------------------------------------------------------
# Define the BleDfuServer class
#------------------------------------------------------------------------------
class BleDfuServer(object):

    #--------------------------------------------------------------------------
    # Adjust these handle values to your peripheral device requirements.
    #--------------------------------------------------------------------------
    ctrlpt_handle      = 0x12
    ctrlpt_cccd_handle = 0x13
    data_handle        = 0x10

    pkt_receipt_interval = 10
    pkt_payload_size     = 20

    #--------------------------------------------------------------------------
    #
    #--------------------------------------------------------------------------
    def __init__(self, target_mac, binfile_path, datfile_path):

        self.binfile_path = binfile_path
        self.datfile_path = datfile_path

        if(debug):
            print(datfile_path, binfile_path)
            print("gatttool -b '%s' -t random --interactive" % target_mac)

        self.ble_conn = pexpect.spawn("gatttool -b '%s' -t random --interactive" % target_mac)

        # remove next line comment for pexpect detail tracing.
        #self.ble_conn.logfile = sys.stdout

    #--------------------------------------------------------------------------
    # Connect to peripheral device.
    #--------------------------------------------------------------------------
    def scan_and_connect(self):

        if(debug): print("scan_and_connect")

        try:
            self.ble_conn.expect('\[LE\]>', timeout=10)
        except pexpect.TIMEOUT:
            print("Connect timeout")

        if(debug): print('>>connect')
        self.ble_conn.sendline('connect')

        try:
            self.ble_conn.expect('Connection successful', timeout=10)
        except pexpect.TIMEOUT:
            print("Connect timeout")

    #--------------------------------------------------------------------------
    # Wait for notification to arrive.
    # Example format: "Notification handle = 0x0019 value: 10 01 01"
    #--------------------------------------------------------------------------
    def _dfu_wait_for_notify(self):

        while True:
            if(debug): print("(f)dfu_wait_for_notify")

            if not self.ble_conn.isalive():
                print("connection not alive")
                return None

            try:
                index = self.ble_conn.expect('Notification handle = .*? \r\n', timeout=30)

            except pexpect.TIMEOUT:
                #
                # The gatttool does not report link-lost directly.
                # The only way found to detect it is monitoring the prompt '[CON]'
                # and if it goes to '[   ]' this indicates the connection has
                # been broken.
                # In order to get a updated prompt string, issue an empty
                # sendline('').  If it contains the '[   ]' string, then
                # raise an exception. Otherwise, if not a link-lost condition,
                # continue to wait.
                #


                if(debug): print('>>')
                self.ble_conn.sendline('')
                string = self.ble_conn.before
                if(debug): print("Timeout of some sort:" + string)
                if '[   ]' in string:
                    print('Connection lost! {0}.{1}'.format(name, os.getpid()))
                    raise Exception('Connection Lost')
                return None

            if index == 0:
                after = self.ble_conn.after
                hxstr = after.split()[3:]
                handle = long(float.fromhex(hxstr[0]))
                return hxstr[2:]

            else:
                print("unexpeced index: {0}".format(index))
                return None

    #--------------------------------------------------------------------------
    # Parse notification status results
    #--------------------------------------------------------------------------
    def _dfu_parse_notify(self, notify):

        if len(notify) < 3:
            print("notify data length error")
            return None

        dfu_oper = notify[0]
        oper_str = DFU_oper_to_str[dfu_oper]

        if oper_str == "RESPONSE":

            dfu_process = notify[1]
            dfu_status  = notify[2]

            process_str = DFU_proc_to_str[dfu_process]
            status_str  = DFU_status_to_str[dfu_status]

            print("oper: {0}, proc: {1}, status: {2}".format(oper_str, process_str, status_str))

            if oper_str == "RESPONSE" and status_str == "SUCCESS":
                return "OK"
            else:
                return "FAIL"

        if oper_str == "PKT_RCPT_NOTIF":

            byte1 = int(notify[4], 16)
            byte2 = int(notify[3], 16)
            byte3 = int(notify[2], 16)
            byte4 = int(notify[1], 16)

            receipt = 0
            receipt = receipt + (byte1 << 24)
            receipt = receipt + (byte2 << 16)
            receipt = receipt + (byte3 << 8)
            receipt = receipt + (byte4 << 0)

            print("PKT_RCPT: {0:8}".format(receipt))

            return "OK"


    #--------------------------------------------------------------------------
    # Send two bytes: command + option
    #--------------------------------------------------------------------------
    def _dfu_state_set(self, opcode):
        if(debug): 
            print("(f)dfu_state_set")
            print('>>char-write-req 0x%04x %04x' % (self.ctrlpt_handle, opcode))
        
        self.ble_conn.sendline('char-write-req 0x%04x %04x' % (self.ctrlpt_handle, opcode))

        # Verify that command was successfully written
        try:
            res = self.ble_conn.expect('.* written successfully', timeout=10)
        except(pexpect.TIMEOUT):
            print("State timeout")

    def _dfu_set_prn(self, prn):
        if(debug):
            print("(f)dfu_set_prn")
            print('>>char-write-req 0x%04x 02%04x' % (self.ctrlpt_handle, prn))

        self.ble_conn.sendline('char-write-req 0x%04x 02%04x' % (self.ctrlpt_handle, prn))

        # Verify that command was successfully written
        try:
            self.ble_conn.expect('.* written successfully', timeout=10)
        except(pexpect.TIMEOUT):
            print("State timeout")

    def _dfu_calc_crc(self):
        if(debug): 
            print("(f)dfu_calc_crc")
            print('>>char-write-req 0x%04x 03' % (self.ctrlpt_handle))

        self.ble_conn.sendline('char-write-req 0x%04x 03' % (self.ctrlpt_handle))

        # Verify that command was successfully written
        try:
            self.ble_conn.expect('.* written successfully', timeout=10)
        except(pexpect.TIMEOUT, e):
            print("State timeout")

        return self._dfu_wait_for_notify()

    def _dfu_execute(self):
        if(debug): 
            print("(f)dfu_execute")
            print('>>char-write-req 0x%04x 04' % (self.ctrlpt_handle))
        self.ble_conn.sendline('char-write-req 0x%04x 04' % (self.ctrlpt_handle))

        # Verify that command was successfully written
        try:
            self.ble_conn.expect('.* written successfully', timeout=10)
        except(pexpect.TIMEOUT):
            print("State timeout")

        return self._dfu_wait_for_notify()

    #--------------------------------------------------------------------------
    # Send one byte: command
    #--------------------------------------------------------------------------
    def _dfu_state_set_byte(self, opcode):
        if(debug): print('>>char-write-req 0x%04x %02x' % (self.ctrlpt_handle, opcode))
        self.ble_conn.sendline('char-write-req 0x%04x %02x' % (self.ctrlpt_handle, opcode))

        # Verify that command was successfully written
        try:
            self.ble_conn.expect('.* written successfully', timeout=10)
        except(pexpect.TIMEOUT):
            print("State timeout")

    def _dfu_cmd_send_req(self, opcode, data_arr):
        if(debug): print("(f)dfu_cmd_send_req")
        hex_str = convert_array_to_hex_string(data_arr)
        if(debug): print('>>char-write-req 0x%04x %04x%s' % (self.ctrlpt_handle, opcode, hex_str))
        self.ble_conn.sendline('char-write-req 0x%04x %04x%s' % (self.ctrlpt_handle, opcode, hex_str))

    #--------------------------------------------------------------------------
    # Send 3 bytes: PKT_RCPT_NOTIF_REQ with interval of 10 (0x0a)
    #--------------------------------------------------------------------------
    def _dfu_pkt_rcpt_notif_req(self):

        opcode = 0x080000
        opcode = opcode + (self.pkt_receipt_interval << 8)

        if(debug): print('>>char-write-req 0x%04x %06x' % (self.ctrlpt_handle, opcode))
        self.ble_conn.sendline('char-write-req 0x%04x %06x' % (self.ctrlpt_handle, opcode))

        # Verify that command was successfully written
        try:
            self.ble_conn.expect('.* written successfully', timeout=10)
        except(pexpect.TIMEOUT, e):
            print("Send PKT_RCPT_NOTIF_REQ timeout")

    #--------------------------------------------------------------------------
    # Send an array of bytes: request mode
    #--------------------------------------------------------------------------
    def _dfu_data_send_req(self, data_arr):
        if(debug): print("(f)dfu_data_send_req")
        hex_str = convert_array_to_hex_string(data_arr)
        #print hex_str
        if(debug): print('>>char-write-req 0x%04x %s' % (self.data_handle, hex_str))
        self.ble_conn.sendline('char-write-req 0x%04x %s' % (self.data_handle, hex_str))

        # Verify that data was successfully written
        try:
            self.ble_conn.expect('.* written successfully', timeout=10)
        except(pexpect.TIMEOUT, e):
            print("Data timeout")

    #--------------------------------------------------------------------------
    # Send an array of bytes: command mode
    #--------------------------------------------------------------------------
    def _dfu_data_send_cmd(self, data_arr):
        # print("(f)dfu_data_send_cmd")
        hex_str = convert_array_to_hex_string(data_arr)
        #print hex_str
        # print('>>char-write-cmd 0x%04x %s' % (self.data_handle, hex_str))
        self.ble_conn.sendline('char-write-cmd 0x%04x %s' % (self.data_handle, hex_str))

    #--------------------------------------------------------------------------
    # Enable DFU Control Point CCCD (Notifications)
    #--------------------------------------------------------------------------
    def _dfu_enable_cccd(self):
        if(debug): print("(f)dfu_enable_cccd")
        cccd_enable_value_array_lsb = convert_uint16_to_array(0x0001)
        cccd_enable_value_hex_string = convert_array_to_hex_string(cccd_enable_value_array_lsb)
        if(debug): print('>>char-write-req 0x%04x %s' % (self.ctrlpt_cccd_handle, cccd_enable_value_hex_string))
        self.ble_conn.sendline('char-write-req 0x%04x %s' % (self.ctrlpt_cccd_handle, cccd_enable_value_hex_string))

        # Verify that CCCD was successfully written
        try:
            self.ble_conn.expect('.* written successfully', timeout=10)
        except(pexpect.TIMEOUT):
            print("CCCD timeout")

    #--------------------------------------------------------------------------
    # Send the Init info (*.dat file contents) to peripheral device.
    #--------------------------------------------------------------------------
    def _dfu_send_init(self):

        if(debug): print("dfu_send_init")

         # Send 'START DFU' + Application Command
        self._dfu_state_set(0x0601)
        self._dfu_wait_for_notify()

        # Open the DAT file and create array of its contents
        bin_array = array('B', open(self.datfile_path, 'rb').read())

        # Transmit binary image size
        self.dat_size = len(bin_array)
        if(debug): print("len ", self.dat_size)
        dat_size_array_lsb = convert_uint32_to_array(len(bin_array))
        if(debug): print(dat_size_array_lsb)
        self._dfu_cmd_send_req(0x0101,dat_size_array_lsb)

        # Wait for INIT DFU notification (indicates flash erase completed)
        notify = self._dfu_wait_for_notify()
        if(debug):
            print("Notify:")
            print(notify)

        # Transmit Init info
        segment_count = 1
        if(debug):
            print(self.dat_size, self.pkt_payload_size, self.dat_size/self.pkt_payload_size)
            print(bin_array)
        
        for i in range(0, self.dat_size, self.pkt_payload_size):

            progress(i,self.dat_size)

            segment = bin_array[i:i + self.pkt_payload_size]
            self._dfu_data_send_cmd(segment)

            if(debug): print("segment #%i" % (segment_count))

            if (segment_count % self.pkt_receipt_interval) == 0:
                notify = self._dfu_wait_for_notify()
                if(debug): print("Notify:", notify)

                # if notify == None:
                #     raise Exception("no notification received")

                # dfu_status = self._dfu_parse_notify(notify)

                # if dfu_status == None or dfu_status != "OK":
                #     raise Exception("bad notification status")

            segment_count += 1

        self._dfu_calc_crc()
        self._dfu_execute()

    def _dfu_send_app(self):

        if(debug): print("dfu_send_app")

        # Transmit binary image size
        hex_size_array_lsb = convert_uint32_to_array(len(self.bin_array))

        if(debug):
            print("len ", self.hex_size)
            print(hex_size_array_lsb)

            print(self.hex_size, self.pkt_payload_size, self.hex_size/self.pkt_payload_size)

        max_txfer_size = 0x1000
        total = self.hex_size/max_txfer_size+1
        for j in range(0, total):

            progress(j,total)

            offset=j*max_txfer_size
            payload = self.bin_array[offset:offset+max_txfer_size]
            if(debug): print("Offset: %i, Payload size: %i" % (offset, len(payload)))

            # Send 'START DFU' + Application Command
            self._dfu_state_set(0x0602)
            if(debug): print(self._dfu_wait_for_notify())

            # self._dfu_cmd_send_req(0x0102,hex_size_array_lsb)
            self._dfu_cmd_send_req(0x0102,convert_uint32_to_array(len(payload)))

            # Wait for INIT DFU notification (indicates flash erase completed)
            notify = self._dfu_wait_for_notify()
            if(debug):
                print("Notify:")
                print(notify)

            segment_count = 1
            for i in range(0, len(payload), self.pkt_payload_size):

                segment = payload[i:i + self.pkt_payload_size]
                self._dfu_data_send_cmd(segment)

                if (segment_count % self.pkt_receipt_interval) == 0:
                    if(debug): print("segment #%i,%i : %i" % (j, segment_count, len(segment)))
                    notify = self._dfu_wait_for_notify()
                    if(debug): print("Notify:", notify)

                    # if notify == None:
                    #     raise Exception("no notification received")

                    # dfu_status = self._dfu_parse_notify(notify)

                    # if dfu_status == None or dfu_status != "OK":
                    #     raise Exception("bad notification status")

                segment_count += 1

            self._dfu_calc_crc()
            self._dfu_execute()

    #--------------------------------------------------------------------------
    # Initialize: 
    #    Hex: read and convert hexfile into bin_array 
    #    Bin: read binfile into bin_array
    #--------------------------------------------------------------------------
    def input_setup(self):

        if(debug): print("input_setup")

        if self.binfile_path == None:
            raise Exception("input invalid")

        name, extent = os.path.splitext(self.binfile_path)

        if extent == ".bin":
            self.bin_array = array('B', open(self.binfile_path, 'rb').read())
            self.hex_size = len(self.bin_array)
            if(debug): print("bin array size: ", self.hex_size)
            return

        if extent == ".hex":
            intelhex = IntelHex(self.binfile_path)
            self.bin_array = intelhex.tobinarray()
            self.hex_size = len(self.bin_array)
            if(debug): print("bin array size: ", self.hex_size)
            return

        raise Exception("input invalid")

    #--------------------------------------------------------------------------
    # Send the binary firmware image to peripheral device.
    #--------------------------------------------------------------------------
    def dfu_send_image(self):

        if(debug): print("(f)dfu_send_image")

        # Enable Notifications
        self._dfu_enable_cccd()

        # set the PRN
        self._dfu_set_prn(0x0A00)

        # Transmit the Init image (DAT).
        self._dfu_send_init()

        # Send the APP
        self._dfu_send_app()

        # Wait a bit for copy on the peer to be finished
        time.sleep(1)

    #--------------------------------------------------------------------------
    # Disconnect from peer device if not done already and clean up. 
    #--------------------------------------------------------------------------
    def disconnect(self):
        if(debug): print('>>exit')
        self.ble_conn.sendline('exit')
        self.ble_conn.close()

#------------------------------------------------------------------------------
#
#------------------------------------------------------------------------------
def main():

    print("DFU Server start")

    try:
        parser = optparse.OptionParser(usage='%prog -z <zip_file> -a <dfu_target_address>\n\nExample:\n\tdfu.py -z DFU.zip -a cd:e3:4a:47:1c:e4',
                                       version='0.6')

        parser.add_option('-a', '--address',
                  action='store',
                  dest="address",
                  type="string",
                  default=None,
                  help='DFU target address.'
                  )

        parser.add_option('-z', '--zip',
                  action='store',
                  dest="zipfile",
                  type="string",
                  default=None,
                  help='zip file to be used.'
                  )

        options, args = parser.parse_args()

    except Exception as e:
        print(e)
        print("For help use --help")
        sys.exit(2)

    unpacker = None

    try:
        ''' Validate input parameters '''

        if not options.address:
            parser.print_help()
            exit(2)

        binfile  = None
        datfile  = None

        if options.zipfile != None:
            unpacker = Unpacker()

            binfile, datfile = unpacker.unpack_zipfile(options.zipfile)

        else:
            parser.print_help()
            exit(2)

        ''' Start of Device Firmware Update processing '''

        ble_dfu = BleDfuServer(options.address.upper(), binfile, datfile)

        # Initialize inputs
        ble_dfu.input_setup()

        # Connect to peer device.
        ble_dfu.scan_and_connect()

        # Transmit the hex image to peer device.
        ble_dfu.dfu_send_image()

        # Wait to receive the disconnect event from peripheral device.
        time.sleep(1)

        # Disconnect from peer device if not done already and clean up. 
        ble_dfu.disconnect()

    except Exception as e:
        print(e)
        pass

    except:
        pass

    # If Unpacker for zipfile used then delete Unpacker
    if unpacker != None:
        unpacker.delete()

    print("DFU Server done")

#------------------------------------------------------------------------------
#
#------------------------------------------------------------------------------
if __name__ == '__main__':

    # Do not litter the world with broken .pyc files.
    sys.dont_write_bytecode = True

    main()
