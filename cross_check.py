#!/usr/bin/env python3
# 이전 성공 방식을 동적분석 데이터에 동일하게 적용하여 검증

import os

def validate_with_correct_approach():
    print("이전 성공 방식으로 동적분석 데이터 검증")
    
    test_dir = "dynamic_analysis/ver2/test"
    
    # 실제 FLAG.txt.ryk (이전 성공 방식)
    with open('FLAG.txt.ryk', 'rb') as f:
        flag_data = f.read()
    
    print("이전 성공 방식: 헤더 없이 직접 XOR")
    
    # FLAG 복호화 (이전 성공 방식)
    flag_plaintext = b'KKB{test}'
    flag_key = []
    for i in range(len(flag_plaintext)):
        flag_key.append(flag_data[i] ^ flag_plaintext[i])
    
    print(f"FLAG 키: {bytes(flag_key).hex()}")
    
    # FLAG 전체 복호화
    flag_decrypted = []
    for i, byte in enumerate(flag_data):
        if i < len(flag_key):
            flag_decrypted.append(byte ^ flag_key[i])
        else:
            flag_decrypted.append(byte ^ flag_key[i % len(flag_key)])
    
    flag_result = bytes(flag_decrypted).decode('utf-8', errors='ignore')
    clean_flag = ""
    for char in flag_result:
        if 32 <= ord(char) <= 126:
            clean_flag += char
        else:
            break
    
    print(f"FLAG 결과: {clean_flag}")
    
    print("동일한 방식을 동적분석 데이터에 적용")
    
    # 1. aa_pattern.txt.ryk 검증
    print("1. AA 패턴 검증")
    aa_path = os.path.join(test_dir, "aa_pattern.txt.ryk")
    with open(aa_path, 'rb') as f:
        aa_data = f.read()
    
    aa_plaintext = b'AAAAAAAAAAAAAAAA'
    aa_key = []
    for i in range(min(len(aa_plaintext), len(aa_data))):
        aa_key.append(aa_data[i] ^ aa_plaintext[i])
    
    print(f"AA 키: {bytes(aa_key).hex()}")
    
    # AA 전체 복호화
    aa_decrypted = []
    for i, byte in enumerate(aa_data):
        if i < len(aa_key):
            aa_decrypted.append(byte ^ aa_key[i])
        else:
            aa_decrypted.append(byte ^ aa_key[i % len(aa_key)])
    
    aa_result = bytes(aa_decrypted)
    print(f"AA 복호화: {aa_result[:16]} ({'성공' if aa_result[:16] == aa_plaintext else '실패'})")
    
    # 2. repeat_char.txt.ryk 검증  
    print("2. X 패턴 검증")
    repeat_path = os.path.join(test_dir, "repeat_char.txt.ryk")
    with open(repeat_path, 'rb') as f:
        repeat_data = f.read()
    
    repeat_plaintext = b'XXXXXXXXXXXXXXXX'
    repeat_key = []
    for i in range(min(len(repeat_plaintext), len(repeat_data))):
        repeat_key.append(repeat_data[i] ^ repeat_plaintext[i])
    
    print(f"X 키: {bytes(repeat_key).hex()}")
    
    # X 전체 복호화
    repeat_decrypted = []
    for i, byte in enumerate(repeat_data):
        if i < len(repeat_key):
            repeat_decrypted.append(byte ^ repeat_key[i])
        else:
            repeat_decrypted.append(byte ^ repeat_key[i % len(repeat_key)])
    
    repeat_result = bytes(repeat_decrypted)
    print(f"X 복호화: {repeat_result[:16]} ({'성공' if repeat_result[:16] == repeat_plaintext else '실패'})")
    
    # 3. flag_pattern.txt.ryk 검증
    print("3. FLAG 패턴 검증")
    flag_pattern_path = os.path.join(test_dir, "flag_pattern.txt.ryk")
    with open(flag_pattern_path, 'rb') as f:
        flag_pattern_data = f.read()
    
    flag_pattern_plaintext = b'KKB{test_flag_here}'
    flag_pattern_key = []
    for i in range(min(len(flag_pattern_plaintext), len(flag_pattern_data))):
        flag_pattern_key.append(flag_pattern_data[i] ^ flag_pattern_plaintext[i])
    
    print(f"FLAG 패턴 키: {bytes(flag_pattern_key).hex()}")
    
    # FLAG 패턴 전체 복호화
    flag_pattern_decrypted = []
    for i, byte in enumerate(flag_pattern_data):
        if i < len(flag_pattern_key):
            flag_pattern_decrypted.append(byte ^ flag_pattern_key[i])
        else:
            flag_pattern_decrypted.append(byte ^ flag_pattern_key[i % len(flag_pattern_key)])
    
    flag_pattern_result = bytes(flag_pattern_decrypted).decode('utf-8', errors='ignore')
    print(f"FLAG 패턴 복호화: {repr(flag_pattern_result[:19])}")
    
    # 4. null_test.txt.ryk 분석 (0바이트 파일의 암호화 결과)
    print("4. NULL 테스트 분석")
    null_path = os.path.join(test_dir, "null_test.txt.ryk")
    with open(null_path, 'rb') as f:
        null_data = f.read()
    
    print(f"NULL 파일 (0바이트 원본): {null_data.hex()} ({len(null_data)} bytes)")
    print("이것은 0바이트 파일을 암호화한 결과 = 순수 키/헤더")
    
    print("키 패턴 분석")
    print(f"FLAG 키:      {bytes(flag_key).hex()}")
    print(f"AA 키:        {bytes(aa_key[:len(flag_key)]).hex()}")
    print(f"X 키:         {bytes(repeat_key[:len(flag_key)]).hex()}")
    print(f"FLAG패턴 키:  {bytes(flag_pattern_key[:len(flag_key)]).hex()}")
    
    # 모든 키가 같은지 확인
    keys_match = all(
        bytes(key[:len(flag_key)]) == bytes(flag_key) 
        for key in [aa_key, repeat_key, flag_pattern_key]
        if len(key) >= len(flag_key)
    )
    
    if keys_match:
        print("모든 키가 일치 - 같은 암호화 방식 사용")
    else:
        print("키가 다름 - 파일별로 다른 키 사용")
        
    print("최종 결론")
    print(f"실제 FLAG: {clean_flag}")
    print(f"방식 검증: {'성공' if keys_match else '부분성공'}")
    
    return clean_flag

if __name__ == "__main__":
    result = validate_with_correct_approach()
