***Setting***
Documentation
...            [Author]         "K Savithri"
...            [Maintenance]    "TRS I & V Tools Bangalore Team"
...			   [Changed Edited on 27-04-2017] the BTS configuration was changed to plain IPV6 and added few additional checks after LTE 3094 was introduced 
Force Tags    CLOUD_R4P    FL18    CA_E2ET_BTSTRSPZ    CRT

Library        OperatingSystem
Library        ute_fsmaccess
Library        ute_admin_infomodel
Library        ute_wtssim
Library   	   ta_emss  host=${host}  port=${port}
Library        Collections
Library        ute_tshark
Library        ute_syslog
Library        XML     lxml=True
Library        String
Resource       ${CURDIR}/../../OAM/LTE648/resources/migration.robot
Resource       ${CURDIR}/../../OAM/LTE648/resources/Enable_BTS.robot
Resource       ${CURDIR}/../resources/common_variables.txt
Library 	   ${CURDIR}/../resources/add_cerificates.py
Library    	   ${CURDIR}/../lib/ute_trs_web/Port_Mirroring.py
Resource       ${CURDIR}/../../OAM/LTE648/resources/Admin_Common_Library.robot
Resource       ${CURDIR}/../resources/Common_Traffic_Mirroring.robot

# You can use Suite settings to enable something on start and teardwon it on stop
Suite setup         Start syslog for 'enb' and 'iphy'
Suite teardown      Stop syslog for 'enb' and 'iphy'

*** Variables ***
${port}           			${4001}
${host}           			10.0.1.1
${BTSSM_IP_ADDRESS}=        192.168.255.129
${USER_NAME}=               Nemuadmin
${PASSWORD}=                nemuuser
${Certificate_Chain}		${CURDIR}/../resources/Certificates/TOOLS_TRSIV.p12
${Certificate_Chain_Pswd}	nokia
${Emssim_certificate}		/opt/emssim/proxy/ssl/clientcert.p12 
${Emssim_certificate_Pswd}	emssim
${tshark_alias_eth1}        tshark_eth1
${tshark_eth1_interface}    eth1
${Traffic_lib}				${CURDIR}/../Traffic_mirroring/lib/traffic_capturing.py
${trs_manual_ip}          	192.168.255.129
${dst_mac_address}			aa:bb:cc:dd:ee:ff
${path} 					/home/flexi1/UPLOADS
${source_file}              /tmp/192.168.255.129_scf.xml
${target_file}              ${CURDIR}/BTS_TRS_comm.xml
${wireshark_debugg}                           ${OUTPUT_DIR}/TRSIV\ BLR\ BTSOAM
*** Test Cases ***
[1]TRS_1076_TLS12_support_BTSOM

    Setup Pre-Conditions	
	Traffic Capturing Started
    wait_for_enb_discovery
	Traffic Capturing Stopped
	TLS Connection verification	
	Trigger download from NMS
	Trigger upload from NMS	
	[Teardown]  Setup Post-Conditions
	
*** Keywords ***
Setup Pre-Conditions
	Create wireshark directories
	Configuring Ipv6 On enB And Vm
	Check BTS and TRS is commissioned or configured
	Get Required Values from Scfc File
    Certificates installation
    Perform Parameter commissioning without reset	 IPNO:1:omsTls:forced
    Sleep    60
	Setup Emss
	Sleep	60
	Enb Configuration Should Be Discovered

Get Required Values from Scfc File
	Get BTS_TRS File	
	${enb_ip}=   Get Element Text     ${target_file}    .//managedObject[@class="NOKLTE:IPNO"]/p[@name="cPlaneIpv6Address"]
	${ems_ip}=   Get Element Text     ${target_file}    .//managedObject[@class="NOKLTE:IPNO"]/p[@name="oamIpAddr"]	
	Set Global Variable		${enb_ip}
	Set Global Variable		${ems_ip}
	
Get BTS_TRS File
    Download BTS_TRS File from eNB
    Copy File   ${source_file}  ${target_file}
	
Certificates installation
	add_ats_certificate_trust_chain    ${Emssim_certificate}    ${Emssim_certificate_Pswd}
#    add_additional_ca_certificates    ${Emssim_certificate}    ${Emssim_certificate_Pswd}
	
TLS Connection verification
	${client_output}=  Run     tshark -r ${EXECDIR}/tshark_output -d tcp.port==8003,ssl -Y 'ssl&&ip.src==${enb_ip}'
	Should Not Be Empty		${client_output}
	Should contain		${client_output}	TLSv1.2
	${server_output}=  Run     tshark -r ${EXECDIR}/tshark_output -d tcp.port==8003,ssl -Y 'ssl&&ip.src==${ems_ip}'
	Should Not Be Empty		${server_output}
	Should contain		${server_output}	TLSv1.2 
#Added As A Part Of LTE3094	
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/tshark_output		 tcp.port==${secure_port},ssl -Y ${client_hello_filter} && 'ip.src == ${ems_ip}' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/tshark_output		 tcp.port==${secure_port},ssl -Y ${server_hello_filter} && 'ip.src == ${enb_ip}' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/tshark_output		 (ssl.handshake.type == 2)&&((ssl.handshake.ciphersuite == 0x0039)||(ssl.handshake.ciphersuite == 0x002f)||(ssl.handshake.ciphersuite == 0x000a))
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/tshark_output		 (ssl.handshake.type == 1)&&((ssl.handshake.ciphersuite == 0x0039)||(ssl.handshake.ciphersuite == 0x002f)||(ssl.handshake.ciphersuite == 0x000a))
	Should Be True			${TLS_1.0_packets}  == 0
	
Traffic Capturing Started
	Remove Files        ${EXECDIR}/tshark_output
	Setup Tshark    interface=${tshark_eth1_interface}  log_dir=${EXECDIR}   log_name=tshark_output		alias=${tshark_alias_eth1}
	Start Capturing         capture_filter=tcp         alias=${tshark_alias_eth1}
	Traffic Mirroring at local stream Measpoint B started  
	
    
Traffic Capturing Stopped	
	Sleep   10
	Stop Capturing          alias=${tshark_alias_eth1}
	Traffic Mirroring at local stream Measpoint B Stopped
	
Trigger download from NMS
	Check software build on eNB before update
	Download Software to emss
	Sleep	300
    Run     mv ${EXECDIR}/${build_filename} /home/ute/output/build/
	wait_for_enb_discovery
	Remove Files        ${EXECDIR}/tshark_output
	Start Capturing         capture_filter='tcp'         alias=${tshark_alias_eth1}
	Traffic Mirroring at local stream Measpoint B started 
	Run Keyword And Ignore Error	Run Emssim Command  sw_update   /home/ute/output/build/${build_filename}	
	Sleep   10
    Stop Capturing          alias=${tshark_alias_eth1}	
	Secured Download Traffic Monitoring
	Sleep   500	
	Traffic Mirroring at local stream Measpoint B Stopped
	
Secured Download Traffic Monitoring
	${output}=  Run     tshark -r ${EXECDIR}/tshark_output -d tcp.port==8003,ssl -Y 'ssl&&ip.src==${enb_ip}&&ip.dst==${ems_ip}'
	Should Not Be Empty		${output}
	Should contain		${output}	TLSv1.2

Download Software to emss
	Run     wget http://files.ute.inside.nsn.com/builds/enb/base/ -O /tmp/linkcontent  
	${rc}	 ${build_number} =     Run and Return RC and Output	 	perl ${CURDIR}/../../OAM/LTE648/resources/get_higher_buildname.pl ${current_build} 2>/tmp/stderr.txt 
	Run Keyword If 		'${build_number}'==' '  Perform software download for Downgrade     ELSE    Perform software download for Upgrade
	#Run Keyword And Ignore Error	Run Emssim Command    sw_update    ${EXECDIR}/${build_number}_release_BTSSM_downloadable.zip
	
Trigger upload from NMS
	Run Keyword And Ignore Error	Run		sudo rm ${path}/WBTSHWData.xml	
	OperatingSystem.File Should Not Exist	${path}/WBTSHWData.xml
	wait_for_enb_discovery
	Remove Files        ${EXECDIR}/tshark_output
	Start Capturing         capture_filter='tcp'         alias=${tshark_alias_eth1}
	Traffic Mirroring at local stream Measpoint B started
	Run Emssim Command	file_upload		1
	Sleep   10
    Stop Capturing          alias=${tshark_alias_eth1}
	Traffic Mirroring at local stream Measpoint B Stopped
	OperatingSystem.File Should Exist	${path}/WBTSHWData.xml
	Secured Upload Traffic Monitoring
	
Secured Upload Traffic Monitoring
	${output}=  Run     tshark -r ${EXECDIR}/tshark_output -d tcp.port==6001,ssl -Y 'ssl'
	Should Not Be Empty		${output}
	Should contain		${output}	TLSv1.2
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/tshark_output		 tcp.port==6001,ssl -Y 'ip.src == ${ems_ip}' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/tshark_output		 tcp.port==6001,ssl -Y 'ip.src == ${enb_ip}' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
#   Below lines to be checked and uncommented during first execution
#	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/tshark_output		 tcp.port==6001,ssl -Y 'ip.src == ${enb_ip}' && ('ssl.record.version == 0x0303'|| 'ssl.record.version == 0x0302')
#	Should Be True			${TLS_1.0_packets}  > 0
	
Setup Post-Conditions
	Teardown Tshark		alias=${tshark_alias_eth1}
	Teardown Emss
	Run Keyword if Test Failed      Collect all logs
	
Collect all logs
	Collect snapshot and save logs
	Run    sudo cp ${EXECDIR}/tshark_output ${wireshark_debugg}                           
	