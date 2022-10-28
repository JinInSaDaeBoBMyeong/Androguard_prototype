## 권한 출력
def permission(a,d,dx,flag=1):
    if flag:
        print(f"[*]PERMISSION EXTRACTING")
    permission = a.get_permissions()
    permission = a.get_requested_aosp_permissions()
    if flag:
        print(f"{permission}\n")
    return permission


## 활동 내역 출력
def activity(a,d,dx,flag=1):
    if flag:
        print(f"[*]Activity Extracting")
    start_activity = a.get_main_activities()
    if flag:
        print(f"Starting with {start_activity}")
    activity = a.get_activities()
    if flag:
        print(f"Kind of Activity: {activity}\n")
    return activity

## 서비스 관련 출력
def services(a,d,dx,flag=1):
    if flag:
        print(f"[*]Services Extracting")
    service = a.get_services()
    if flag:
        print(f"service list:{service}\n")
    return service
    
## receivers 관련 출력
def receivers(a,d,dx,flag=1):
    if flag:
        print(f"[*]receivers Extracting")
    receiver = a.get_receivers()
    if flag:
        print(f"receiver list: {receiver}\n")
    return receiver


##opcode 개수
def opcode_cnt(a,d,dx,flag=1):
    if flag:
        print(f"[*]Opcode Extracting")
    from collections import defaultdict
    from operator import itemgetter
    c = defaultdict(int)

    for method in dx.get_methods():
        if method.is_external():
            continue
        m = method.get_method()
        for ins in m.get_instructions():
            c[(ins.get_op_value(), ins.get_name())] += 1
    
    RESULT = {}
    
    for k, v in sorted(c.items(), key=itemgetter(1), reverse=True):
        if flag:
            print(k[0], '-->',  v)
        RESULT[k[0]]=v
    return RESULT

##API 함수
def API(a,d,dx,flag =0):
    res = []
    # Write Method Calls to a .txt file.......///
    for method in dx.get_methods():
        for _, call, _ in method.get_xref_to():
            temp_list = call.class_name.split('/')
            if temp_list[0] == "Landroid":
                if temp_list[1] == "content" or temp_list[1] == "app" or temp_list[1] == "bluetooth" or temp_list[1] == "location" or temp_list[1] == "media" or temp_list[1] == "net" or temp_list[1] == "nfc" or temp_list[1] == "provider" or temp_list[1] == "telecom" or temp_list[1] == "telephony":
                    res.append(temp_list[-1] + call.name)
    return list(res)


## res 파일 내부에 들어있는 파일들 중 .dex 파일 감지
dex_byte_code = b'\x64\x65\x78\x0a\x30\x33\x35\x00'
def file_res(a,d,dx):
    count = 0
    for i in a.get_files():
        if ('asset' in i) or ('res' in i):
            result = a.get_file(i)
            if result[:8] == dex_byte_code:
                count+=1
    return count