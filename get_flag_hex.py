#!/usr/bin/env python3
# 실제 E01에서 추출한 FLAG.txt.ryk 파일의 hex 데이터 확인

def analyze_flag_file():
    print("실제 E01 원본 FLAG.txt.ryk 분석")
    
    try:
        # 실제 FLAG.txt.ryk 파일 읽기
        with open('FLAG.txt.ryk', 'rb') as f:
            actual_data = f.read()
        
        print(f"파일 크기: {len(actual_data)} bytes")
        print(f"전체 Hex: {actual_data.hex()}")
        print(f"처음 16바이트: {actual_data[:16].hex()}")
        print(f"마지막 16바이트: {actual_data[-16:].hex()}")
        
        # 이전 분석 데이터와 비교
        previous_hex = "11d1665cfab6fe29589e8e01e86ebd9159764110e390110da1729f84c006c81b365fc642736a9177935a0263ca7bb3ef"
        
        print("이전 분석과 비교")
        print(f"이전 예상 hex: {previous_hex}")
        print(f"실제 파일 hex: {actual_data.hex()}")
        
        if actual_data.hex() == previous_hex:
            print("일치 이전 분석 정확")
            return True
        elif actual_data.hex().startswith(previous_hex[:32]):  # 처음 16바이트만 비교
            print("부분 일치 (처음 부분)")
            return True
        else:
            print("불일치 - 새로운 분석 필요")
            return False
            
    except Exception as e:
        print(f"오류: {e}")
        return False

if __name__ == "__main__":
    analyze_flag_file()
