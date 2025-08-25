#!/usr/bin/env python3
# 동적분석 데이터로 FLAG 복호화 방식 완전 검증

import os

def analyze_dynamic_test_files():
    print("동적분석 테스트 파일 완전 검증")
    
    # 테스트 파일 경로
    test_dir = "dynamic_analysis/ver2/test"
    
    # 실제 FLAG.txt.ryk 읽기
    with open('FLAG.txt.ryk', 'rb') as f:
        flag_data = f.read()
    print(f"실제 FLAG.txt.ryk: {len(flag_data)} bytes")
    
    print(f"\nStep 1: null_test.txt.ryk에서 순수 키스트림 추출")
    # null_test.txt.ryk = 0바이트 원본 → 순수 키스트림
    null_path = os.path.join(test_dir, "null_test.txt.ryk")
    with open(null_path, 'rb') as f:
        null_keystream = f.read()
    
    print(f"null 키스트림: {null_keystream.hex()} ({len(null_keystream)} bytes)")
    
    print(f"\nStep 2: 알려진 평문으로 키 역산 검증")
    
    # aa_pattern.txt.ryk 분석 (AAAAAAAAAAAAAAAA)
    aa_path = os.path.join(test_dir, "aa_pattern.txt.ryk")
    with open(aa_path, 'rb') as f:
        aa_encrypted = f.read()
    
    aa_plaintext = b'AAAAAAAAAAAAAAAA'  # 16바이트 A 패턴
    print(f"AA 패턴 암호화: {aa_encrypted.hex()} ({len(aa_encrypted)} bytes)")
    
    # AA 패턴에서 키 역산 (28바이트 헤더 제외)
    if len(aa_encrypted) > 28:
        aa_ciphertext = aa_encrypted[28:]  # 헤더 제외
        aa_key = bytes(c ^ p for c, p in zip(aa_ciphertext, aa_plaintext))
        print(f"AA에서 역산된 키: {aa_key.hex()}")
    
    # repeat_char.txt.ryk 분석 (XXXXXXXXXXXXXXXX)  
    repeat_path = os.path.join(test_dir, "repeat_char.txt.ryk")
    with open(repeat_path, 'rb') as f:
        repeat_encrypted = f.read()
        
    repeat_plaintext = b'XXXXXXXXXXXXXXXX'  # 16바이트 X 패턴
    print(f"X 패턴 암호화: {repeat_encrypted.hex()} ({len(repeat_encrypted)} bytes)")
    
    # X 패턴에서 키 역산
    if len(repeat_encrypted) > 28:
        repeat_ciphertext = repeat_encrypted[28:]
        repeat_key = bytes(c ^ p for c, p in zip(repeat_ciphertext, repeat_plaintext))
        print(f"X에서 역산된 키: {repeat_key.hex()}")
    
    print(f"\nStep 3: FLAG.txt.ryk에 동일한 방식 적용")
    
    # FLAG에서 키 역산 (KKB{test} 가정)
    flag_plaintext = b'KKB{test}'
    if len(flag_data) >= 28 + len(flag_plaintext):
        flag_ciphertext = flag_data[28:28+len(flag_plaintext)]  # 28바이트 헤더 제외
        flag_key = bytes(c ^ p for c, p in zip(flag_ciphertext, flag_plaintext))
        print(f"FLAG에서 역산된 키: {flag_key.hex()}")
        
        # 전체 FLAG 복호화
        full_flag_ciphertext = flag_data[28:]  # 헤더 제외
        decrypted = []
        for i, c in enumerate(full_flag_ciphertext):
            key_byte = flag_key[i % len(flag_key)]
            decrypted.append(c ^ key_byte)
        
        decrypted_text = bytes(decrypted).decode('utf-8', errors='ignore')
        print(f"FLAG 복호화 결과: {repr(decrypted_text)}")
        
        # 깨끗한 FLAG 추출
        clean_flag = ""
        for char in decrypted_text:
            if 32 <= ord(char) <= 126:
                clean_flag += char
            else:
                break
                
        print(f"최종 FLAG: {clean_flag}")
        
    print(f"\nStep 4: 키 일관성 검증")
    
    # 모든 역산된 키들이 같은 패턴인지 확인
    keys_to_compare = []
    if 'aa_key' in locals():
        keys_to_compare.append(("AA 패턴", aa_key))
    if 'repeat_key' in locals():
        keys_to_compare.append(("X 패턴", repeat_key))
    if 'flag_key' in locals():
        keys_to_compare.append(("FLAG", flag_key))
    
    print("키 비교:")
    for name, key in keys_to_compare:
        print(f"  {name}: {key.hex()}")
    
    # 키들이 같은 패턴인지 확인
    if len(keys_to_compare) >= 2:
        base_key = keys_to_compare[0][1]
        all_same = True
        for name, key in keys_to_compare[1:]:
            if key[:len(base_key)] != base_key[:len(key)]:
                all_same = False
                break
        
        if all_same:
            print("모든 키가 일관된 패턴!")
        else:
            print("키 패턴 불일치")
    
    print(f"\nStep 5: 28바이트 헤더 분석")
    
    # 28바이트 헤더가 순수 키스트림과 같은지 확인
    flag_header = flag_data[:28]
    print(f"FLAG 헤더: {flag_header.hex()}")
    print(f"null 키스트림: {null_keystream.hex()}")
    
    if flag_header == null_keystream:
        print("FLAG 헤더 = null 키스트림 (완전 일치!)")
    else:
        print("FLAG 헤더 ≠ null 키스트림")
        
    return clean_flag if 'clean_flag' in locals() else None

if __name__ == "__main__":
    result = analyze_dynamic_test_files()
