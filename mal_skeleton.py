from androguard.misc import AnalyzeAPK, get_default_session
import pandas as pd
import os
from SCRIPTS.BASE import *
from collections import Counter
import hashlib
from tqdm import tqdm

#컬럼 합칠 예정
ALL_PERMISSION=['android.permission.ACCEPT_HANDOVER', 'android.permission.ACCESS_BACKGROUND_LOCATION', 'android.permission.ACCESS_BLOBS_ACROSS_USERS', 'android.permission.ACCESS_CHECKIN_PROPERTIES', 'android.permission.ACCESS_COARSE_LOCATION', 'android.permission.ACCESS_FINE_LOCATION', 'android.permission.ACCESS_LOCATION_EXTRA_COMMANDS', 'android.permission.ACCESS_MEDIA_LOCATION', 'android.permission.ACCESS_NETWORK_STATE', 'android.permission.ACCESS_NOTIFICATION_POLICY', 'android.permission.ACCESS_WIFI_STATE', 'android.permission.ACCOUNT_MANAGER', 'android.permission.ACTIVITY_RECOGNITION', 'com.android.voicemail.permission.ADD_VOICEMAIL', 'android.permission.ANSWER_PHONE_CALLS', 'android.permission.BATTERY_STATS', 'android.permission.BIND_ACCESSIBILITY_SERVICE', 'android.permission.BIND_APPWIDGET', 'android.permission.BIND_AUTOFILL_SERVICE', 'android.permission.BIND_CALL_REDIRECTION_SERVICE', 'android.permission.BIND_CARRIER_MESSAGING_CLIENT_SERVICE', 'android.permission.BIND_CARRIER_MESSAGING_SERVICE', 'android.permission.BIND_CARRIER_SERVICES', 'android.permission.BIND_CHOOSER_TARGET_SERVICE', 'android.permission.BIND_COMPANION_DEVICE_SERVICE', 
'android.permission.BIND_CONDITION_PROVIDER_SERVICE', 'android.permission.BIND_CONTROLS', 'android.permission.BIND_DEVICE_ADMIN', 'android.permission.BIND_DREAM_SERVICE', 'android.permission.BIND_INCALL_SERVICE', 'android.permission.BIND_INPUT_METHOD', 'android.permission.BIND_MIDI_DEVICE_SERVICE', 'android.permission.BIND_NFC_SERVICE', 'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE', 'android.permission.BIND_PRINT_SERVICE', 'android.permission.BIND_QUICK_ACCESS_WALLET_SERVICE', 'android.permission.BIND_QUICK_SETTINGS_TILE', 'android.permission.BIND_REMOTEVIEWS', 'android.permission.BIND_SCREENING_SERVICE', 'android.permission.BIND_TELECOM_CONNECTION_SERVICE', 'android.permission.BIND_TEXT_SERVICE', 'android.permission.BIND_TV_INPUT', 'android.permission.BIND_TV_INTERACTIVE_APP', 'android.permission.BIND_VISUAL_VOICEMAIL_SERVICE', 'android.permission.BIND_VOICE_INTERACTION', 'android.permission.BIND_VPN_SERVICE', 'android.permission.BIND_VR_LISTENER_SERVICE', 'android.permission.BIND_WALLPAPER', 'android.permission.BLUETOOTH', 'android.permission.BLUETOOTH_ADMIN', 'android.permission.BLUETOOTH_ADVERTISE', 'android.permission.BLUETOOTH_CONNECT', 'android.permission.BLUETOOTH_PRIVILEGED', 'android.permission.BLUETOOTH_SCAN', 'android.permission.BODY_SENSORS', 'android.permission.BODY_SENSORS_BACKGROUND', 'android.permission.BROADCAST_PACKAGE_REMOVED', 
'android.permission.BROADCAST_SMS', 'android.permission.BROADCAST_STICKY', 'android.permission.BROADCAST_WAP_PUSH', 'android.permission.CALL_COMPANION_APP', 'android.permission.CALL_PHONE', 'android.permission.CALL_PRIVILEGED', 'android.permission.CAMERA', 'android.permission.CAPTURE_AUDIO_OUTPUT', 'android.permission.CHANGE_COMPONENT_ENABLED_STATE', 'android.permission.CHANGE_CONFIGURATION', 'android.permission.CHANGE_NETWORK_STATE', 'android.permission.CHANGE_WIFI_MULTICAST_STATE', 'android.permission.CHANGE_WIFI_STATE', 'android.permission.CLEAR_APP_CACHE', 'android.permission.CONTROL_LOCATION_UPDATES', 'android.permission.DELETE_CACHE_FILES', 'android.permission.DELETE_PACKAGES', 'android.permission.DELIVER_COMPANION_MESSAGES', 'android.permission.DIAGNOSTIC', 'android.permission.DISABLE_KEYGUARD', 'android.permission.DUMP', 'android.permission.EXPAND_STATUS_BAR', 'android.permission.FACTORY_TEST', 'android.permission.FOREGROUND_SERVICE', 'android.permission.GET_ACCOUNTS', 'android.permission.GET_ACCOUNTS_PRIVILEGED', 'android.permission.GET_PACKAGE_SIZE', 'android.permission.GET_TASKS', 'android.permission.GLOBAL_SEARCH', 'android.permission.HIDE_OVERLAY_WINDOWS', 'android.permission.HIGH_SAMPLING_RATE_SENSORS', 'android.permission.INSTALL_LOCATION_PROVIDER', 'android.permission.INSTALL_PACKAGES', 'com.android.launcher.permission.INSTALL_SHORTCUT', 'android.permission.INSTANT_APP_FOREGROUND_SERVICE', 'android.permission.INTERACT_ACROSS_PROFILES', 'android.permission.INTERNET', 'android.permission.KILL_BACKGROUND_PROCESSES', 'android.permission.LAUNCH_MULTI_PANE_SETTINGS_DEEP_LINK', 'android.permission.LOADER_USAGE_STATS', 'android.permission.LOCATION_HARDWARE', 'android.permission.MANAGE_DOCUMENTS', 'android.permission.MANAGE_EXTERNAL_STORAGE', 'android.permission.MANAGE_MEDIA', 'android.permission.MANAGE_ONGOING_CALLS', 'android.permission.MANAGE_OWN_CALLS', 'android.permission.MANAGE_WIFI_INTERFACES', 'android.permission.MANAGE_WIFI_NETWORK_SELECTION', 'android.permission.MASTER_CLEAR', 'android.permission.MEDIA_CONTENT_CONTROL', 'android.permission.MODIFY_AUDIO_SETTINGS', 'android.permission.MODIFY_PHONE_STATE', 'android.permission.MOUNT_FORMAT_FILESYSTEMS', 'android.permission.MOUNT_UNMOUNT_FILESYSTEMS', 'android.permission.NEARBY_WIFI_DEVICES', 'android.permission.NFC', 'android.permission.NFC_PREFERRED_PAYMENT_INFO', 'android.permission.NFC_TRANSACTION_EVENT', 'android.permission.OVERRIDE_WIFI_CONFIG', 'android.permission.PACKAGE_USAGE_STATS', 'android.permission.PERSISTENT_ACTIVITY', 'android.permission.POST_NOTIFICATIONS', 'android.permission.PROCESS_OUTGOING_CALLS', 'android.permission.QUERY_ALL_PACKAGES', 'android.permission.READ_ASSISTANT_APP_SEARCH_DATA', 'android.permission.READ_BASIC_PHONE_STATE', 'android.permission.READ_CALENDAR', 'android.permission.READ_CALL_LOG', 'android.permission.READ_CONTACTS', 'android.permission.READ_EXTERNAL_STORAGE', 'android.permission.READ_HOME_APP_SEARCH_DATA', 'android.permission.READ_INPUT_STATE', 'android.permission.READ_LOGS', 'android.permission.READ_MEDIA_AUDIO', 'android.permission.READ_MEDIA_IMAGES', 'android.permission.READ_MEDIA_VIDEO', 'android.permission.READ_NEARBY_STREAMING_POLICY', 'android.permission.READ_PHONE_NUMBERS', 'android.permission.READ_PHONE_STATE', 'android.permission.READ_PRECISE_PHONE_STATE', 'android.permission.READ_SMS', 'android.permission.READ_SYNC_SETTINGS', 'android.permission.READ_SYNC_STATS', 'com.android.voicemail.permission.READ_VOICEMAIL', 'android.permission.REBOOT', 'android.permission.RECEIVE_BOOT_COMPLETED', 'android.permission.RECEIVE_MMS', 'android.permission.RECEIVE_SMS', 'android.permission.RECEIVE_WAP_PUSH', 'android.permission.RECORD_AUDIO', 'android.permission.REORDER_TASKS', 'android.permission.REQUEST_COMPANION_PROFILE_APP_STREAMING', 'android.permission.REQUEST_COMPANION_PROFILE_AUTOMOTIVE_PROJECTION', 'android.permission.REQUEST_COMPANION_PROFILE_COMPUTER', 'android.permission.REQUEST_COMPANION_PROFILE_WATCH', 'android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND', 'android.permission.REQUEST_COMPANION_SELF_MANAGED', 'android.permission.REQUEST_COMPANION_START_FOREGROUND_SERVICES_FROM_BACKGROUND', 'android.permission.REQUEST_COMPANION_USE_DATA_IN_BACKGROUND', 'android.permission.REQUEST_DELETE_PACKAGES', 'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS', 'android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.REQUEST_OBSERVE_COMPANION_DEVICE_PRESENCE', 'android.permission.REQUEST_PASSWORD_COMPLEXITY', 'android.permission.RESTART_PACKAGES', 'android.permission.SCHEDULE_EXACT_ALARM', 'android.permission.SEND_RESPOND_VIA_MESSAGE', 'android.permission.SEND_SMS', 'com.android.alarm.permission.SET_ALARM', 'android.permission.SET_ALWAYS_FINISH', 'android.permission.SET_ANIMATION_SCALE', 'android.permission.SET_DEBUG_APP', 'android.permission.SET_PREFERRED_APPLICATIONS', 'android.permission.SET_PROCESS_LIMIT', 'android.permission.SET_TIME', 'android.permission.SET_TIME_ZONE', 'android.permission.SET_WALLPAPER', 'android.permission.SET_WALLPAPER_HINTS', 'android.permission.SIGNAL_PERSISTENT_PROCESSES', 'android.permission.SMS_FINANCIAL_TRANSACTIONS', 'android.permission.START_FOREGROUND_SERVICES_FROM_BACKGROUND', 'android.permission.START_VIEW_APP_FEATURES', 'android.permission.START_VIEW_PERMISSION_USAGE', 'android.permission.STATUS_BAR', 'android.permission.SUBSCRIBE_TO_KEYGUARD_LOCKED_STATE', 'android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.TRANSMIT_IR', 'com.android.launcher.permission.UNINSTALL_SHORTCUT', 'android.permission.UPDATE_DEVICE_STATS', 'android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION', 'android.permission.USE_BIOMETRIC', 'android.permission.USE_EXACT_ALARM', 'android.permission.USE_FINGERPRINT', 'android.permission.USE_FULL_SCREEN_INTENT', 'android.permission.USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER', 'android.permission.USE_SIP', 'android.permission.UWB_RANGING', 'android.permission.VIBRATE', 'android.permission.WAKE_LOCK', 'android.permission.WRITE_APN_SETTINGS', 'android.permission.WRITE_CALENDAR', 'android.permission.WRITE_CALL_LOG', 'android.permission.WRITE_CONTACTS', 'android.permission.WRITE_EXTERNAL_STORAGE', 'android.permission.WRITE_GSERVICES', 'android.permission.WRITE_SECURE_SETTINGS', 'android.permission.WRITE_SETTINGS', 'android.permission.WRITE_SYNC_SETTINGS', 'com.android.voicemail.permission.WRITE_VOICEMAIL']
ALL_MANIFEST=[]
ALL_OPCODE=[]

#MANIFEST 세팅
ALL_MANIFEST=['ACTIVITY','SERVICE','RECEIVER']

#OPCODE 세팅
for i in range(256):
    ALL_OPCODE.append(i)

#API 세팅
ALL_API= pd.read_csv(".\\SCRIPTS\\apilist.csv")
ALL_API=list(ALL_API.to_dict().keys())

#데이터 프레임 세팅
COLUMN= ['name','sha256','min-sdk','target-sdk','max-sdk']+ALL_PERMISSION+ ALL_MANIFEST+ALL_OPCODE+ALL_API+['res_asset_dex_cnt','family','label']
df = pd.DataFrame(columns=COLUMN)
df = df.to_dict('list')                      

#error 관련 데이터 셋
df_error = pd.DataFrame(columns=['name','sha256'])
df_error = df_error.to_dict('list')

#Config if you want
PATH= "./INPUT/"

if __name__=="__main__":
    for up_folder in os.listdir(PATH):
        print(f"[*]DOING {up_folder}")
        for target_file in tqdm(os.listdir(PATH+up_folder)):
            try:
                TARGET = PATH+up_folder+"//"+target_file
                # print(f"[*]Doing {target_file}")
                
                tmp=[]
                
                tmp.append(target_file)
                
                ## 전반적 분석 진행
                a,d,dx = AnalyzeAPK(TARGET)
                
                ##'sha256','min-sdk','target-sdk','max-sdk'
                with open(TARGET,"rb") as file:
                    file=file.read()
                enc_1 = hashlib.sha256(file).hexdigest()
                tmp.append(enc_1)
                
                #min-sdk
                tmp.append(a.get_min_sdk_version())
                #target-sdk
                tmp.append(a.get_target_sdk_version())
                #max-sdk
                tmp.append(a.get_max_sdk_version())
                
                
                #PERMISSION 추출
                PERMISSION = permission(a)

                #컬럼 PERMISSION 세팅 - 1                
                for i in ALL_PERMISSION:
                    if i in PERMISSION:
                        tmp.append(1)
                    else:
                        # df[i].append('0')
                        tmp.append(0)
                        
                # df['ACTIVITY'].append(MANIFEST[0])
                tmp.append(len(activity(a)))
                # df['SERVICE'].append(MANIFEST[1])
                tmp.append(len(services(a)))
                # df['RECEIVER'].append(MANIFEST[2])
                tmp.append(len(receivers(a)))

                ##opcode 수
                OPCODE_CNT = opcode_cnt(dx)
                
                #OPCODE 세팅
                for i,_ in enumerate(ALL_OPCODE):
                    if i in OPCODE_CNT.keys():
                        tmp.append(OPCODE_CNT[i])
                    else:
                        tmp.append(0)
                    
                ##api_call
                API_CNT = Counter(API(dx))
                
                for i,j in enumerate(ALL_API):
                    if j in API_CNT.keys():
                        tmp.append(API_CNT[j])
                    else:
                        tmp.append(0)
                
                tmp.append(file_res(a))
                    
                # df['family'].append(up_folder)
                tmp.append(up_folder)
                # df['label'].append(1)
                tmp.append(1)
            except KeyboardInterrupt:
                break
            except:
                try:
                    print("ERROR IS OCCURED")
                    with open(TARGET,"rb") as file:
                        file=file.read()
                    enc = hashlib.sha256(file).hexdigest()
                    df_error['name'].append(target_file)
                    df_error['sha256'].append(enc)
                    continue
                except:
                    break
            for i,j in enumerate(COLUMN):
                df[j].append(tmp[i])
                
    df = pd.DataFrame.from_dict(df)
    df.to_csv("./RESULT/mal_done.csv")
    df_error = pd.DataFrame.from_dict(df_error)
    df_error.to_csv("./ERROR/mal_error.csv")