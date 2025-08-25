# 카카오뱅크 보안기술 개발 및 침해대응 담당자 과제

## 과제 개요
랜섬웨어에 감염된 E01 디스크 이미지를 분석하는 과제

**최종 결과**: `KKB{test}`

## 스크립트 설명

### 핵심 복호화 도구
- **`final_accurate_decryption.py`** - 메인 복호화 스크립트, Known-Plaintext Attack으로 FLAG 도출
- **`get_flag_hex.py`** - E01에서 추출한 FLAG.txt.ryk 파일의 바이너리 데이터 분석
- **`dynamic_validation_complete.py`** - 11개 테스트 파일을 사용한 복호화 알고리즘 완전 검증

### 추가 검증 도구  
- **`cross_check.py`** - 동적분석 데이터를 활용한 교차 검증
