*** Settings ***
Documentation
...            [Author]         "Nandini R"
...            [Maintenance]    "TRS I & V Tools Bangalore Team"

Force Tags       CLOUD_F	CA_E2ET_BTSTRSPZ    FL00    FL17A    CRT

Library			XML    use_lxml=${True}
Library			ta_emss    host=${host}    port=${port}    WITH NAME     FLEXI_EMSS
Resource		${CURDIR}/../../OAM/LTE648/resources/Admin_Common_Library.robot
Library			${CURDIR}/../lib/ute_trs_web/common.py
Library			${CURDIR}/../lib/ute_trs_web/ChangePasswd.py
Library			${CURDIR}/../resources/add_cerificates.py
Resource			${CURDIR}/../resources/Common_wireshark.robot
Suite setup      Start syslog for 'enb' and 'iphy'
Suite teardown   Stop syslog for 'enb' and 'iphy'

***Variables***
${delta_file}						${CURDIR}/../resources/Configure_remote_syslog_server.xml
${port} 							${4001}
${host} 	        				10.0.1.1
${secure_port}						8003
${Certificate_Chain}				${CURDIR}/../resources/Certificates/TOOLS_TRSIV.p12
${Certificate_Chain_Pswd}			nokia
${Emssim_certificate}				/opt/emssim/proxy/ssl/clientcert.p12
${Emssim_certificate_Pswd}			emssim
${client_hello_filter}				'ssl.handshake.type==1'
${server_hello_filter}				'ssl.handshake.type==2'
${cipher_suite_filter}				'ssl.handshake.ciphersuite==0x00ff'
${client_key_exchange_filter}		'ssl.handshake.type==16'
${CMP_IP}							10.62.65.164
${Remote_Syslog}					10.43.73.76
${rsyslog_Cert}						${CURDIR}/../resources/chained_cert/Remote_Syslog/rsyslog_cert.pem
${rsyslog_Cacert}					${CURDIR}/../resources/chained_cert/Remote_Syslog/rsyslog_cacert.pem
${rsyslog_private_key}				${CURDIR}/../resources/chained_cert/Remote_Syslog/privkey.pem
${backup_private_key}				${CURDIR}/../resources/chained_cert/Remote_Syslog/backup_privkey.pem
${private_key}						/root/cert/privkey.pem
${cacert}							/root/cert/rsyslog_cacert.pem
${cert}								/root/cert/rsyslog_cert.pem
${rsyslog_Conf_file}				${CURDIR}/../resources/chained_cert/Remote_Syslog/rsyslog.conf
${Conf_file}						/etc/rsyslog.conf
${backup_Conf_file}					/etc/Backup_rsyslog.conf

***Test Cases***
[1][1.0] SEC_TLS12_support_Syslog_SEM_TRSWeb_UA

#Pre-condition:
	Check BTS and TRS is commissioned or configured
	Setup Tshark    interface=eth3  log_dir=/tmp   log_name=tshark_output

#Step1:
	Install 4 layer Chained Certificates on BTS and Remote syslog server

#Step2:
	Login to BTS SEM using BTS S1 IP
	Monitor remote SEM connection by Wireshark
	
#Step3:
	Open the TRS web portal using BTS S1 IP from remote
	Monitor HTTPS traffic by Wireshark
	
#Step4:
	Configure remote syslog server
	Monitor Remote syslog traffic
	
#Step5:
	Certificates installation
	Perform Parameter commissioning without reset    IPNO:1:omsTls:forced
	Sleep   20
	Monitor Secure TLS traffic

*** Keywords ***
Login to BTS SEM using BTS S1 IP
	Traffic Capturing Started
	${var}=		check_btssm_credentials		host_ip=10.0.1.2	username=Nemuadmin		password=nemuuser
	Should Be True		'${var}'=='True'
	Sleep	30
	Traffic Capturing Stopped
	
Monitor remote SEM connection by Wireshark
	${client_output}=  Run     tshark -r /tmp/tshark_output -d tcp.port==6001,ssl -Y 'ssl&&ip.src==10.0.1.1' 2>/dev/null
	Should Not Be Empty		${client_output}
	Should contain		${client_output}	TLSv1.2
	Should contain		${client_output}	Client Hello
	${server_output}=  Run     tshark -r /tmp/tshark_output -d tcp.port==6001,ssl -Y 'ssl&&ip.src==10.0.1.2' 2>/dev/null
	Should Not Be Empty		${server_output}
	Should contain		${server_output}	TLSv1.2
	Should contain		${server_output}	Server Hello
	
	${client_output}=  Run     tshark -r /tmp/tshark_output -d tcp.port==12000,ssl -Y 'ssl&&ip.src==10.0.1.1' 2>/dev/null
	Should Not Be Empty		${client_output}
	Should contain		${client_output}	TLSv1.2
	Should contain		${client_output}	Client Hello
	${server_output}=  Run     tshark -r /tmp/tshark_output -d tcp.port==12000,ssl -Y 'ssl&&ip.src==10.0.1.2' 2>/dev/null
	Should Not Be Empty		${server_output}
	Should contain		${server_output}	TLSv1.2
	Should contain		${server_output}	Server Hello
#Added As A Part Of LTE3094 	
#	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${secure_port},ssl -Y ${client_hello_filter} && 'ip.src == ${10.0.1.1}' && 'ssl.record.version == 0x0301'
#	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${secure_port},ssl -Y ${server_hello_filter} && 'ip.src == ${10.0.1.2}' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 (ssl.handshake.type == 2)&&((ssl.handshake.ciphersuite == 0x0039)||(ssl.handshake.ciphersuite == 0x002f)||(ssl.handshake.ciphersuite == 0x000a))
	Should Be True			${TLS_1.0_packets}  == 0
#	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 (ssl.handshake.type == 1)&&((ssl.handshake.ciphersuite == 0x0039)||(ssl.handshake.ciphersuite == 0x002f)||(ssl.handshake.ciphersuite == 0x000a))
#	Should Be True			${TLS_1.0_packets}  == 0

Open the TRS web portal using BTS S1 IP from remote
	Traffic Capturing Started
	${var}=		common.login_web		10.0.1.2		Nemuadmin		nemuuser
	Sleep	30
	Traffic Capturing Stopped

Monitor HTTPS traffic by Wireshark
	${client_output}=  Run     tshark -r /tmp/tshark_output -d tcp.port==443,ssl -Y 'ssl&&ip.src==10.0.1.1' 2>/dev/null
	Should Not Be Empty		${client_output}
	Should contain		${client_output}	TLSv1.2
	Should contain		${client_output}	Client Hello
	${server_output}=  Run     tshark -r /tmp/tshark_output -d tcp.port==443,ssl -Y 'ssl&&ip.src==10.0.1.2' 2>/dev/null
	Should Not Be Empty		${server_output}
	Should contain		${server_output}	TLSv1.2
	Should contain		${server_output}	Server Hello
#Added As A Part Of LTE3094	
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${secure_port},ssl -Y ${client_hello_filter} && 'ip.src == 10.0.1.1' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${secure_port},ssl -Y ${server_hello_filter} && 'ip.src == 10.0.1.2' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 (ssl.handshake.type == 2)&&((ssl.handshake.ciphersuite == 0x0039)||(ssl.handshake.ciphersuite == 0x002f)||(ssl.handshake.ciphersuite == 0x000a))
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 (ssl.handshake.type == 1)&&((ssl.handshake.ciphersuite == 0x0039)||(ssl.handshake.ciphersuite == 0x002f)||(ssl.handshake.ciphersuite == 0x000a))
	Should Be True			${TLS_1.0_packets}  == 0

Configure remote syslog server
	Traffic Capturing Started
	Perform ENB Recommissioning without reset	${delta_file}
	Sleep		30
	Traffic Capturing Stopped

Monitor Remote syslog traffic
	${client_output}=  Run     tshark -r /tmp/tshark_output -d tcp.port==16400,ssl -Y 'ssl&&ip.src==10.0.1.2' 2>/dev/null
	Should Not Be Empty		${client_output}
	Should contain		${client_output}	TLSv1.1
	Should contain		${client_output}	Client Hello
	${server_output}=  Run     tshark -r /tmp/tshark_output -d tcp.port==16400,ssl -Y 'ssl&&ip.src==10.43.73.76' 2>/dev/null
	Should Not Be Empty		${server_output}
	Should contain		${server_output}	TLSv1.1
	Should contain		${server_output}	Server Hello
#Added As A Part Of LTE3094	
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${secure_port},ssl -Y ${client_hello_filter} && 'ip.src == 10.0.1.2' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${secure_port},ssl -Y ${server_hello_filter} && 'ip.src == 10.0.1.1' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 (ssl.handshake.type == 2)&&((ssl.handshake.ciphersuite == 0x0039)||(ssl.handshake.ciphersuite == 0x002f)||(ssl.handshake.ciphersuite == 0x000a))
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 (ssl.handshake.type == 1)&&((ssl.handshake.ciphersuite == 0x0039)||(ssl.handshake.ciphersuite == 0x002f)||(ssl.handshake.ciphersuite == 0x000a))
	Should Be True			${TLS_1.0_packets}  == 0
	
Monitor Secure TLS traffic
	Traffic Capturing Started
	Setup Emss
	Sleep	30
	Recover Emss Connection
	Sleep	30
	Traffic Capturing Stopped
	${output}=		Run     tshark -r /tmp/tshark_output -d tcp.port==${secure_port},ssl -Y ${client_hello_filter} 2>/dev/null
	Should Not Be Empty		${output}
	${output}=		Run     tshark -r /tmp/tshark_output -d tcp.port==${secure_port},ssl -Y ${server_hello_filter} 2>/dev/null
	Should Not Be Empty		${output}
	Should contain		${output}	TLSv1.2
	${output}=		Run     tshark -r /tmp/tshark_output -d tcp.port==${secure_port},ssl -Y ${cipher_suite_filter} 2>/dev/null
	Should Not Be Empty		${output}
	${output}=		Run     tshark -r /tmp/tshark_output -d tcp.port==${secure_port},ssl -Y ${client_key_exchange_filter} 2>/dev/null
	Should Not Be Empty		${output}
	Should contain		${output}	TLSv1.2
#Added As A Part Of LTE3094	
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${secure_port},ssl -Y ${client_hello_filter} && 'ip.src == 10.0.1.1' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${secure_port},ssl -Y ${server_hello_filter} && 'ip.src == 10.0.1.2' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 (ssl.handshake.type == 2)&&((ssl.handshake.ciphersuite == 0x0039)||(ssl.handshake.ciphersuite == 0x002f)||(ssl.handshake.ciphersuite == 0x000a))
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 (ssl.handshake.type == 1)&&((ssl.handshake.ciphersuite == 0x0039)||(ssl.handshake.ciphersuite == 0x002f)||(ssl.handshake.ciphersuite == 0x000a))
	Should Be True			${TLS_1.0_packets}  == 0
	

Traffic Capturing Started
	Start Capturing         capture_filter=tcp
	Sleep  5

Traffic Capturing Stopped
	Stop Capturing

Install 4 layer Chained Certificates on BTS and Remote syslog server
	Run    cd /opt/NSN/Managers/BTS\\ Site/BTS\\ Site\\ Manager/tools/TRSCommandLineTools && sudo ./start_tool.sh -ne 192.168.255.129 -pw Nemuadmin:nemuuser -restoreVendorCerts && cd -
	Sleep	30
	Perform Parameter commissioning without reset       CERTH:1:cmpServerIpAddress:${CMP_IP} 
    Perform Parameter commissioning without reset       CERTH:1:cmpServerPort:8081
    Perform Parameter commissioning without reset       CERTH:1:caSubjectName:CN=ute_automation_bts_ca3
    Sleep   10
	Run    cd /opt/NSN/Managers/BTS\\ Site/BTS\\ Site\\ Manager/tools/TRSCommandLineTools && sudo ./start_tool.sh -ne 192.168.255.129 -pw Nemuadmin:nemuuser -cmpInitRequest && cd -
    Sleep   80
	
	${ssh_handle}    Open Connection    ${Remote_Syslog}
    Login        root		trsiv123
    Switch Connection      ${ssh_handle}
	SSHLibrary.Get File     ${private_key}   	${backup_private_key}
	SSHLibrary.Put File     ${rsyslog_private_key}   	${private_key}
	SSHLibrary.Put File     ${rsyslog_Cacert}   	${cacert}
	SSHLibrary.Put File     ${rsyslog_cert}   	${cert}
	SSHLibrary.Execute Command		cp ${Conf_file} ${backup_Conf_file}
	SSHLibrary.Put File     ${rsyslog_Conf_file}   	${Conf_file}
	SSHLibrary.Execute Command		service rsyslog restart
    Close Connection
	
Certificates installation
	Run    cd /opt/NSN/Managers/BTS\\ Site/BTS\\ Site\\ Manager/tools/TRSCommandLineTools && sudo ./start_tool.sh -ne 192.168.255.129 -pw Nemuadmin:nemuuser -restoreVendorCerts && cd -
	Sleep	30
    add_ats_certificate_trust_chain    ${Certificate_Chain}    ${Certificate_Chain_Pswd}
    add_additional_ca_certificates    ${Emssim_certificate}    ${Emssim_certificate_Pswd}
	
Uninstall Certificates
	Run    cd /opt/NSN/Managers/BTS\\ Site/BTS\\ Site\\ Manager/tools/TRSCommandLineTools && sudo ./start_tool.sh -ne 192.168.255.129 -pw Nemuadmin:nemuuser -restoreVendorCerts && cd -
	Sleep	30
	${ssh_handle}    Open Connection    ${Remote_Syslog}
    Login        root		trsiv123
    Switch Connection      ${ssh_handle}
	SSHLibrary.Put File     ${backup_private_key}   	${private_key}
	SSHLibrary.Execute Command     cp ${backup_Conf_file} ${Conf_file}
	SSHLibrary.Execute Command     sudo rm -rf ${cacert} ${cert}
    Close Connection
	
Keyword To Run At End
	Uninstall Certificates