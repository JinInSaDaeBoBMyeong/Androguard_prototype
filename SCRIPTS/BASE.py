from collections import defaultdict
from operator import itemgetter

## 권한 출력
def permission(a):
    return a.get_requested_aosp_permissions()

## 활동 내역 출력
def activity(a):
    return a.get_activities()

## 서비스 관련 출력
def services(a):
    return a.get_services()
    
## receivers 관련 출력
def receivers(a):
    return a.get_receivers()


##opcode 개수
def opcode_cnt(dx):
    c = defaultdict(int)

    for method in dx.get_methods():
        if method.is_external():
            continue
        m = method.get_method()
        for ins in m.get_instructions():
            c[ins.get_op_value()] += 1
    
    return c

##API 함수
def API(dx):
    res = []
    # Write Method Calls to a .txt file.......///
    for method in dx.get_methods():
        for _, call, _ in method.get_xref_to():
            temp_list = call.class_name.split('/')
            if temp_list[0] == "Landroid":
                if temp_list[1] in ["content", "app", "bluetooth", "location", "media", "net", "nfc", "provider", "telecom", "telephony"]:
                    res.append(temp_list[-1] + call.name)
    return res


## res 파일 내부에 들어있는 파일들 중 .dex 파일 감지
dex_byte_code = b'\x64\x65\x78\x0a\x30\x33\x35\x00'
def file_res(a):
    count = 0
    for i in a.get_files():
        if ('asset' in i) or ('res' in i):
            result = a.get_file(i)
            if result[:8] == dex_byte_code:
                count+=1
    return count