*** Settings ***
Documentation
...              [Author]      "Nanda"
...              [Maintenance] "TRS I & V Tools Bangalore Team"

#Force Tags      CLOUD_F_IPSEC    CA_E2ET_BTSTRSPZ    FL00    FL17ASP1    CRT

Library        BuiltIn
Library        Process
Library        OperatingSystem
Library        XML     lxml=True
Library        ute_ipsec
Library        ta_emss    host=${host}    port=${port}
Library        ${CURDIR}/../lib/ute_trs_web/SSH.py
Library        ${CURDIR}/../lib/ute_trs_web/TRS_Logout.py
Library        ${CURDIR}/../lib/ute_trs_web/ChangePasswd.py
Resource       ${CURDIR}/../../OAM/LTE648_SOAM/resources/Admin_Common_Library.robot
Resource       ${CURDIR}/../../OAM/LTE648_SOAM/resources/Common_IPSec_Operations.robot
Resource       ${CURDIR}/../../OAM/LTE648_SOAM/resources/Common_Call.robot
Resource       ${CURDIR}/../../OAM/LTE648_SOAM/resources/Enable_BTS.robot
Resource       ${CURDIR}/../resources/Common_Emss.robot
Variables      config

Suite setup      Start syslog for 'enb' and 'iphy'
Suite teardown   Stop syslog for 'enb' and 'iphy'

*** Variables ***
${port}                     ${4001}       # In UTE JSON server listens on port 4001
${host}                     10.0.1.1
${delta_file}               ${CURDIR}/../resources/cnum_delta.xml
${neac_file}                /ffs/run/trs_data/active/keystorage/neac.db
${target_file}              /tmp/192.168.255.129_scf.xml
${enb_ip}                   192.168.255.129
${enb_root_user}            toor4nsn
${enb_root_passwd}          oZPS0POrRieRtu
${USER_NAME}                Nemuadmin
${PASSWORD}                 nemuuser
${enb_user}                 Enbroot1
${enb_paswrd}               Enbuser1@123
${cnum_user}                trsiv
${cnum_paswrd}              trsiv123
${Ldap_port}				8389

*** Test Cases ***
[1]SEC_LOGIN_RESTRICT_CNUM - Login Restrict and Local Account Change

#precondition
    Change IP in Fbox Frames
    Perform VLAN Configuration      ${tl.vlan_ids}
    Obtain start time from eNB

#Step 1
    Login to eNB with username='${USER_NAME}' password='${PASSWORD}' should be successful
    
#Step 2
    Change username='${USER_NAME}' password='${PASSWORD}' to new_username='${enb_user}' new_password='${enb_paswrd}'

#Step 3
    Login to eNB with username='${enb_user}' password='${enb_paswrd}' should be successful

#Step 4
    Peform eNB commissioning with cnum user     ${enb_user}     ${enb_paswrd}       ${delta_file}
    Sleep   60s
    Start EMSSIM & create CNUM user
    
#Step 5
	Traffic Capturing Started
    Download BTS_TRS File from eNB & verify cnum and ldap activation    ${cnum_user}    ${cnum_paswrd}
	
    
#Step 6
    Login to eNB with username='${enb_user}' password='${enb_paswrd}' should get blocked
    Sleep   10s
    Verify intDB logs for block event

#Step 7
    Login to eNB with username='${cnum_user}' password='${cnum_paswrd}' should be successful
	Sleep	60s

#Step 8
    Login to TRS web page with username='${enb_user}' password='${enb_paswrd}' should get blocked 
    Sleep   10s
    Verify intDB logs for block event
    Login to TRS web page with username='${cnum_user}' password='${cnum_paswrd}' should be successful
    
#Restore Environment
    [Teardown]      Keywords to run at end
    
*** Keywords ***
Traffic Capturing Started
	Traffic Mirroring at local stream Measpoint B started
	Start Capturing the packets			TLS.pcap		eth1		TLS_Capture
	
Traffic Capturing Stopped
	Traffic Mirroring at local stream Measpoint B Stopped
	Stop Capturing			TLS_Capture

Change username='${username}' password='${password}' to new_username='${n_username}' new_password='${n_password}'
    LOG     ${username}
    LOG     ${password}
    LOG     ${n_username}
    LOG     ${n_password}
    ${status}    change_local_account_user_credentials   ${username}   ${password}    ${n_username}    ${n_password}
    Should Be True  '${status}' == 'True'
    
    Sleep   20s

Peform eNB commissioning with cnum user
    [Arguments]     ${user_name}    ${password}     ${delta_file}
    Setup Btssm     pw=${user_name}:${password}
    Perform Delta Commissioning     ${delta_file}   pw=${user_name}:${password}
    Teardown Btssm

Start EMSSIM & create CNUM user
    ta_emss.Setup Emss
    Sleep   60s
    ta_emss.Enb Configuration Should Be Discovered
    Sleep   30s
    Run Emssim Command      configure_set ruiSCRoleName <bts/app/system/readWrite>
    Sleep   10s
    Run Emssim Command      ldap_user_add ${cnum_user} ${cnum_paswrd} -a RW
    Sleep   10s
    
Download BTS_TRS File from eNB & verify cnum and ldap activation
    [Arguments]     ${user_name}    ${password}
    Setup Btssm     pw=${user_name}:${password}
    Run Keyword And Ignore Error    Upload Bts Scfc File    pw=${user_name}:${password}
    Teardown Btssm
    Traffic Capturing Stopped
    ${cnum_flag}=     Get Element text    ${target_file}   .//managedObject[@distName="MRBTS-1/LNBTS-1/FTM-1/AMGR-1/LUAC-1"]/p[@name="actRestrictLoginToCnum"]
    Should Be True  '${cnum_flag}' == 'true'
    
    ${ldap_ip}=     Get Element text    ${target_file}   .//managedObject[@distName="MRBTS-1/LNBTS-1/FTM-1/AMGR-1"]/p[@name="primaryLdapServer"]
    Setup Enb Fsm Access
    ${ldapIpStatus}=   Run Keyword and return status   Execute Command On Enb    ping -c 1 '${ldap_ip}' 
    Should Be True     '${ldapIpStatus}'=='True'
    Teardown Enb Fsm Access
	Monitor TLS Traffic
	
Monitor TLS Traffic                                             
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${Ldap_port},ssl -Y ${client_hello_filter} && 'ip.src == 10.0.1.2' && 'ssl.record.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_1.0_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${Ldap_port},ssl -Y ${client_hello_filter} && 'ip.src == 10.0.1.2' && 'ssl.handshake.version == 0x0301'
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_packets_Cipher}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${Ldap_port},ssl -Y (ssl.handshake.type == 1)&&((ssl.handshake.ciphersuite == 0x0039)||(ssl.handshake.ciphersuite == 0x002f)||(ssl.handshake.ciphersuite == 0x000a))
	Should Be True			${TLS_1.0_packets}  == 0
	${TLS_packets}=		Get no.of packets from wireshark		${EXECDIR}/TLS.pcap		 tcp.port==${Ldap_port},ssl -Y (ssl.handshake.version == 0x0302)||(ssl.handshake.version == 0x0303)
	Should Be True			${TLS_1.0_packets}  > 0
	
    
Login to eNB with username='${enb_user}' password='${enb_paswrd}' should get blocked
    LOG     ${enb_user}
    LOG     ${enb_paswrd}
    ${status}    check_btssm_credentials     ${enb_ip}   ${enb_user}    ${enb_paswrd}
    Should Match Regexp     '${status}'     (?im)Login\\s*failed\\s*to\\s*${enb_ip}\\:\\s*BTS\\s*local\\s*account\\s*is\\s*blocked\\.\\s*Contact\\s*your\\s*system\\s*administrator
    
Login to eNB with username='${username}' password='${password}' should be successful
    LOG     ${username}
    LOG     ${password}
    ${status}    check_btssm_credentials     ${enb_ip}   ${username}    ${password}
    Should Be True  '${status}' == 'True'
 
Login to TRS web page with username='${cnum_user}' password='${cnum_paswrd}' should be successful
    ${Output}=      logout_trs_webpage
    Sleep   10s
    ${output} =     SSH.login web   ${enb_ip}    ${cnum_user}   ${cnum_paswrd}
    Log  ${output}
    Should Not Contain  ${output}  blocked

Login to TRS web page with username='${username}' password='${passwrd}' should get blocked
    ${Output}=      logout_trs_webpage
    Sleep   10s
    ${output} =     SSH.login web   ${enb_ip}    ${username}   ${passwrd}
    Log  ${output}
    Should Match Regexp     ${output}   (?im)BTS\\s*local\\s*user\\s*account\\s*is\\s*blocked 

Verify intDB logs for block event
    Run    rm /tmp/intDB* 
    Setup Enb Fsm Access
    ${intDB}=       Execute Command on Enb      ls -tr /ffs/run/trs_data/active/keystorage|grep intDB_|tail -n 1
    Get Enb File   /ffs/run/trs_data/active/keystorage/${intDB}     /tmp/${intDB}
    [Teardown]    Teardown Enb Fsm Access
    Run    gunzip /tmp/${intDB}
    ${output}=      Run     sed -n '/${start_time}/ , $p' /tmp/intDB* >/tmp/intDB.txt 
    ${string}=      Grep File   /tmp/intDB.txt   blockedByCnum
    ${string1}=      Grep File   /tmp/intDB.txt   login restriction enabled
    ${string_status}=    Run Keyword And Return Status   Should Not Be Empty    ${string}
    Run Keyword If  '${string_status}'=='False'     Should Not Be Empty     ${string1}

Obtain start time from eNB
    Setup Enb Fsm Access        
    ${date}=        Execute Command on Enb     date -u 
    Teardown Enb Fsm Access
    ${time}=            Split String     ${date}
    ${start_time}  ${time}=     Split String From Right    @{time}[3]    :   1
    Set Suite Variable    ${start_time}     ${start_time}
    
Restore eNB to old user account
    ${ssh_enb_handle}      Open Connection    ${enb_ip}
    Login                  ${enb_root_user}    ${enb_root_passwd}
    Switch Connection      ${ssh_enb_handle}
    Execute Command     rm -rf ${neac_file}
    Execute Command     reboot
    Close Connection

    Sleep   300s

Keywords to run at end
    Restore eNB to old user account
	Run Keyword if Test Failed    Collect snapshot and save logs
    ta_emss.Teardown Emss
