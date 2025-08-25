#!/usr/bin/env python3
# 실제 E01 원본 50바이트 데이터로 정확한 복호화

def final_decryption():
    print("실제 E01 원본 데이터 최종 복호화")
    
    # 실제 50바이트 원본 데이터
    with open('FLAG.txt.ryk', 'rb') as f:
        actual_data = f.read()
    
    print(f"실제 데이터: {actual_data.hex()}")
    print(f"크기: {len(actual_data)} bytes")
    
    # 이전 분석에서 확인된 키 (KKB{test}에서 역산)
    test_flag = "KKB{test}"
    flag_bytes = test_flag.encode()
    
    print("기존 복호화 방법 (처음 48바이트)")
    # 처음 48바이트로 키 역산
    key_48 = []
    for i in range(len(flag_bytes)):
        key_byte = actual_data[i] ^ flag_bytes[i]
        key_48.append(key_byte)
    
    print(f"처음 8바이트에서 역산된 키: {bytes(key_48).hex()}")
    
    # 48바이트 복호화
    result_48 = []
    data_48 = actual_data[:48]  # 처음 48바이트만
    for i, byte in enumerate(data_48):
        if i < len(key_48):
            result_48.append(byte ^ key_48[i])
        else:
            result_48.append(byte ^ key_48[i % len(key_48)])
    
    try:
        decrypted_48 = bytes(result_48).decode('utf-8', errors='ignore')
        print(f"48바이트 복호화 결과: {repr(decrypted_48)}")
    except:
        print("48바이트 복호화 실패")
    
    print("전체 50바이트 복호화 시도")
    # 전체 50바이트 복호화
    result_50 = []
    for i, byte in enumerate(actual_data):
        if i < len(key_48):
            result_50.append(byte ^ key_48[i])
        else:
            result_50.append(byte ^ key_48[i % len(key_48)])
    
    try:
        decrypted_50 = bytes(result_50).decode('utf-8', errors='ignore')
        print(f"50바이트 복호화 결과: {repr(decrypted_50)}")
    except:
        print("50바이트 복호화 실패")
    
    # 마지막 2바이트 분석
    print("마지막 2바이트 분석")
    last_2_bytes = actual_data[-2:]
    print(f"마지막 2바이트 원본: {last_2_bytes.hex()}")
    
    # 마지막 2바이트 복호화 시도
    last_2_decrypted = []
    for i, byte in enumerate(last_2_bytes):
        key_index = (48 + i) % len(key_48)
        last_2_decrypted.append(byte ^ key_48[key_index])
    
    print(f"마지막 2바이트 복호화: {bytes(last_2_decrypted)}")
    
    # 최종 FLAG 확인
    clean_flag = ""
    for byte in result_50:
        if 32 <= byte <= 126:  # 출력 가능한 ASCII
            clean_flag += chr(byte)
        else:
            break
    
    print(f"\n최종 FLAG: {clean_flag}")
    
    # 검증
    if clean_flag.startswith("KKB{") and "}" in clean_flag:
        flag_end = clean_flag.find("}") + 1
        final_flag = clean_flag[:flag_end]
        print(f"확인된 FLAG: {final_flag}")
        return final_flag
    else:
        print("유효한 FLAG 패턴을 찾을 수 없음")
        return None

if __name__ == "__main__":
    final_decryption()
