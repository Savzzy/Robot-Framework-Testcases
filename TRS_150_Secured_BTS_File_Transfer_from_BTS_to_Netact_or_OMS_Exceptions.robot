***Settings***
Documentation
...            [Author]         "Naman Agrawal"
...            [Maintenance]    "TRS I & V Tools Bangalore Team"

Force Tags    CLOUD_R4P    CA_E2ET_BTSTRSPZ    FL00    FL18    FL17A    CRT

Library     String
Library     ta_emss    host=${host}    port=${port}    with name     FLEXI_EMSS
Resource    ${CURDIR}/../../OAM/LTE648/resources/Enable_BTS.robot
Library        ${CURDIR}/../resources/add_cerificates.py
Resource       ${CURDIR}/../../OAM/LTE648/resources/Admin_Common_Library.robot

# You can use Suite settings to enable something on start and teardown it on stop
Suite setup         Start syslog for 'enb' and 'iphy'
Suite teardown      Stop syslog for 'enb' and 'iphy'

***Variables***
${secure_port}			8003
${EGATE_CONFIG}         ${CURDIR}/../resources/egate_configuration.lua
${EGATE_PORT}           20000
${EDAEMON_PORT}     10000
${port}                         ${4001}       # In UTE JSON server listens on port 4001
${host}                         10.0.1.1
${VM_path}          /home/flexi1/UPLOADS
${enb_path}         /tmp/bts
${Emssim_certificate}       ${CURDIR}/../resources/Certificates/clientcert.p12
${Emssim_certificate_Pswd}  emssim
${Certificate_Chain}        ${CURDIR}/../resources/Certificates/TOOLS_TRSIV.p12
${Certificate_Chain_Pswd}   nokia
${client_hello_filter}				'ssl.handshake.type==1'
${server_hello_filter}				'ssl.handshake.type==2'
***Test Cases***
[1]TRS_150_Secured BTS File Transfer from BTS to Netact or OMS Exceptions

#Pre-Conditions:
    Certificates installation
    Check BTS and TRS is commissioned or configured
#    Check BTS and TRS state
    Change TLS mode     forced
    Setup Emss
    Sleep      60
#   Enb Configuration Should Be Discovered

#Execution Procedure:
#Step1: Upload a file from BTS to OMS using HTTP
    ${output}=      Run     curl --noproxy --tlsv1.2 -k -v -g http://192.168.255.129:6001/SiteEM.xml
    ${output}=      Convert To String       ${output}
    Should Match Regexp      '${output}'      (?im)Recv failure
    

#Step2: Upload a file from BTS to OMS using HTTPS with wrong username and password
    ${output}=      Run     curl --noproxy --tlsv1.2 -k -v -g -u abc:abc https://192.168.255.129:6001//ram/RawAlarmHistory.txt
    ${output}=      Convert To String       ${output}
    Should Match Regexp      '${output}'      (?im)401 Unauthorized

#Step3: File not present at specified location
    ${output}=      Run     curl --noproxy --tlsv1.2 -k -v -g https://192.168.255.129:6001//abc/RawAlarmHistory.txt
    ${output}=      Convert To String       ${output}
    Should Match Regexp      '${output}'      (?im)401 Unauthorized
    
#Step4: Use NetAct to upload  SiteEM.xml file
    Setup Enb Fsm Access    alias=local
    Execute Command On Enb      mv /rom/SiteEM.xml newfile      alias=local
    ${output}=      Run     curl --noproxy --tlsv1.2 -k -v -g https://192.168.255.129:6001/SiteEM.xml    
    ${output}=      Convert To String       ${output}
    Should Match Regexp      '${output}'      (?im)404 Not Found
    Execute Command On Enb      mv newfile /rom/SiteEM.xml      alias=local
	
#Step 5 : Adding As a Part of LTE3094 
	Traffic Capturing Started
	${output}=				Run			openssl s_client -connect 10.0.1.2:443 -tls1
	Traffic Capturing Stopped
	Should Not Match Regexp			${output}			(?i)TLSv1.2
	Check enB doesn't send Server hello
	Traffic Capturing Started
	Run		/opt/NSN/Managers/BTS Site/BTS Site Manager/BTSSiteManager.sh
	Sleep	30s
	Traffic Capturing Stopped
	
    
#Post-Condition:
    [Teardown]      Stop Connection 
    
***Keywords***
Traffic Capturing Started
	Traffic Mirroring at local stream Measpoint B started
	Start Capturing the packets			TLS.pcap		eth1		TLS_Capture
	
Traffic Capturing Stopped
	Traffic Mirroring at local stream Measpoint B Stopped
	Stop Capturing			TLS_Capture
	
Check enB doesn't send Server hello
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${secure_port},ssl -Y ${server_hello_filter} && 'ip.src == 10.0.1.2' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${secure_port},ssl -Y ${client_hello_filter} && 'ip.src == 10.0.1.1' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 1

Certificates installation
    add_ats_certificate_trust_chain    ${Certificate_Chain}    ${Certificate_Chain_Pswd}
    add_additional_ca_certificates    ${Emssim_certificate}    ${Emssim_certificate_Pswd}   

    
Change TLS mode
    [Arguments]                 ${state}
    Perform Parameter commissioning without reset       IPNO:1:omsTls:${state}

Stop Connection
    Teardown Enb Fsm Access    alias=local
    Teardown Emss
    Run Keyword if Test Failed    Collect snapshot and save logs
