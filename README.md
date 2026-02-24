# 🛡️ Steampipe AWS MCP Server

**AWS 인프라를 Steampipe으로 조회하고, MCP(Model Context Protocol) 서버를 통해 Amazon Q Developer에서 자연어로 AWS 인프라 질문 및 보안 컴플라이언스 보고서를 생성합니다.**

## ⚡ 주요 특징

- 🔍 **자연어 AWS 쿼리**: Amazon Q Developer에서 "EC2 인스턴스 목록 보여줘" 같은 자연어로 AWS 리소스 조회
- 🛡️ **AWS 보안 컴플라이언스**: 20개 AWS Foundational Security Best Practices 자동 검사
- 📊 **HTML 보고서**: 대시보드와 AI 분석이 포함된 전문적인 인프라 보고서 자동 생성
- ⚡ **고성능**: 데이터 캐싱과 토큰 절약형 아키텍처
- 🔧 **실용성**: AWS Security Hub 공식 표준 기반

## 🏗️ 아키텍처

```
Amazon Q Developer (MCP 클라이언트)
    ↕ MCP Protocol
MCP 서버 (Python FastMCP)
    ↕ SQL Commands
Steampipe CLI
    ↕ AWS APIs
AWS 클라우드 (EC2, S3, RDS, VPC, IAM 등)
```

## 🛠️ 기술 스택

- **MCP 서버**: Python 3.10+ with FastMCP
- **데이터 조회**: Steampipe v2.3.5 + AWS Plugin v1.29.0
- **보안 표준**: AWS Foundational Security Best Practices
- **보고서**: HTML/CSS with 자동 생성
- **클라이언트**: Amazon Q Developer

## 🚀 설치 및 설정

### 1. 사전 요구사항

```bash
# Steampipe 설치 (이미 설치된 경우 생략)
sudo /bin/sh -c "$(curl -fsSL https://raw.githubusercontent.com/turbot/steampipe/main/install.sh)"

# AWS 플러그인 설치
steampipe plugin install aws

# Python 의존성 설치
pip install mcp
```

### 2. MCP 서버 실행

```bash
python3 server.py
```

### 3. Amazon Q Developer 연동

`~/.aws/amazonq/mcp.json` 파일 생성:

```json
{
  "mcpServers": {
    "steampipe-aws": {
      "command": "/usr/bin/python3",
      "args": ["/path/to/server.py"],
      "env": {}
    }
  }
}
```

## 🔧 MCP 도구 (8개)

| 도구 | 기능 | 사용 예시 |
|------|------|-----------|
| `query_aws` | 임의의 SQL로 AWS 리소스 조회 | "실행중인 EC2만 보여줘" |
| `list_tables` | 사용 가능한 테이블 목록 | "S3 관련 테이블 찾아줘" |
| `describe_table` | 테이블 스키마 확인 | "EC2 테이블 컬럼이 뭐야?" |
| `get_aws_summary` | 28개 카테고리 인프라 요약 | "AWS 인프라 전체 요약해줘" |
| `get_report_data` | AI용 압축 통계 생성 | 보고서 생성 1단계 |
| `generate_html_report` | HTML 보고서 생성 | 보고서 생성 2단계 |
| `run_security_checks` | 기본 8개 보안 체크 | "보안 취약점 체크해줘" |
| `run_all_foundational_security_checks` | 확장 20개 보안 체크 | "종합 보안 감사해줘" |

## 🛡️ AWS 보안 컴플라이언스 (20개 컨트롤)

### CRITICAL (3개)
- **[S3.2]** S3 버킷 퍼블릭 읽기 금지
- **[Lambda.1]** Lambda 함수 퍼블릭 액세스 금지
- **[RDS.1]** RDS 스냅샷 프라이빗 설정

### HIGH (3개)
- **[IAM.1]** IAM 정책 관리자 권한 제한
- **[EC2.2]** VPC 기본 보안그룹 트래픽 차단
- **[CloudTrail.1]** 멀티 리전 CloudTrail 활성화

### MEDIUM (14개)
IAM MFA, S3 설정, EBS 암호화, DynamoDB 백업, Lambda 런타임, SNS 암호화 등

## 📊 사용 예시

### Amazon Q Developer에서

```
🧑 사용자: "AWS 인프라 전체 보고서 만들어줘"

🤖 AI: get_report_data() 호출
      ← 압축된 통계 수신

      AI가 8개 섹션 분석 작성:
      - 전체 요약, 컴퓨팅, 스토리지, 네트워크...

      generate_html_report(분석...) 호출
      ← "report.html 생성 완료 (37KB)"

🧑 사용자: "보안 취약점 체크해줘"

🤖 AI: run_all_foundational_security_checks() 호출
      ← "32개 이슈 발견: Critical 3개, High 2개, Medium 27개"
```

### 직접 Python에서 (모듈화 구조)

```python
import sys
sys.path.append('src')

from config import AppConfig
from mcp_tools import MCPToolsManager

# 설정 로드 및 초기화
config = AppConfig.load()
tools_manager = MCPToolsManager(config)

# 개별 컴포넌트 사용
security_checker = tools_manager.security_checker
report_generator = tools_manager.report_generator

# 보안 체크 실행
results = security_checker.run_checks()  # 기본 8개
results_all = security_checker.run_checks()  # 전체 20개

# 보고서 생성
data = report_generator.generate_summary_data()
# AI 분석 후 HTML 생성
report_path = report_generator.generate_html_report(analysis_dict)
```

## 📈 성능 최적화

- **데이터 캐싱**: 5분간 쿼리 결과 재사용 (`steampipe_client.py`)
- **토큰 절약**: AI에게는 1,600자 압축 통계만 전달 (`report_generator.py`)
- **병렬 처리**: 독립적인 쿼리들을 동시 실행
- **HTML 직접 렌더링**: AI 토큰 소모 없이 데이터 테이블 생성
- **모듈별 로딩**: 필요한 컴포넌트만 메모리 로드
- **설정 기반**: 환경변수로 타임아웃, 캐시 등 튜닝 가능

## 🔍 보안 체크 결과 예시

```
# AWS Foundational Security Report
Generated: 2024-12-07 09:23 UTC
Controls executed: 20 / 339 total available

## Executive Summary
**Total Security Issues**: 32
- Critical Severity: 3
- High Severity: 2
- Medium Severity: 27

**Services Scanned**: 10
- EC2: 3 controls
- S3: 2 controls
- IAM: 2 controls
- Lambda: 2 controls
- DynamoDB: 3 controls
...
```

## 📁 프로젝트 구조 (모듈화)

```
mcp-test/
├── server.py              # MCP 서버 진입점 (37줄)
├── src/                   # 모듈화된 소스 코드
│   ├── config.py          # 설정 관리 (환경변수, 기본값)
│   ├── steampipe_client.py # Steampipe CLI 클라이언트 (캐싱, 에러처리)
│   ├── security_checker.py # AWS 보안 컴플라이언스 체커
│   ├── report_generator.py # HTML 보고서 생성기
│   └── mcp_tools.py       # MCP 도구 등록 및 관리
├── report.html            # 생성된 HTML 보고서 (gitignore)
├── README.md              # 프로젝트 문서
├── .gitignore            # Git 무시 파일
└── steampipe-mod-aws-compliance/  # AWS 표준 참조 (gitignore)
```

### 🏗️ 모듈별 역할

| 모듈 | 역할 | 주요 클래스/함수 |
|------|------|------------------|
| `config.py` | 설정 관리 | `AppConfig`, `SteampipeConfig`, `ReportConfig` |
| `steampipe_client.py` | Steampipe 연동 | `SteampipeClient`, `ResultFormatter` |
| `security_checker.py` | 보안 체크 | `SecurityChecker`, `SecurityControl` |
| `report_generator.py` | 보고서 생성 | `ReportGenerator` |
| `mcp_tools.py` | MCP 통합 | `MCPToolsManager` |

## 🌟 주요 장점

### 1. **실용성**
- AWS Security Hub 공식 표준 사용
- 실제 운영 환경에서 즉시 활용 가능
- 토큰 효율적인 AI 연동

### 2. **확장성**
- 현재 20개 → 향후 339개 컨트롤로 확장 가능
- 새로운 AWS 서비스 쉽게 추가
- 커스텀 보안 정책 구현 가능

### 3. **사용성**
- 자연어로 AWS 인프라 질의
- 전문적인 HTML 보고서 자동 생성
- Amazon Q Developer 완벽 통합

### 4. **유지보수성** ⭐
- **모듈화된 아키텍처**: 관심사 분리로 코드 구조 명확
- **독립적 컴포넌트**: 각 모듈별 개별 수정 및 테스트 가능
- **확장 용이성**: 새 기능을 적절한 모듈에 쉽게 추가
- **37줄 진입점**: 복잡한 로직은 모듈에, 메인은 단순하게

## 📋 환경 요구사항

- **AWS 계정**: 적절한 IAM 권한 필요
- **Python**: 3.10 이상
- **Steampipe**: v2.3.5 이상
- **MCP**: FastMCP 라이브러리
- **클라이언트**: Amazon Q Developer

## 🤝 기여 방법

### 개발자 가이드
1. **이슈 리포팅**: 버그 발견 시 상세한 재현 과정 포함
2. **새로운 보안 컨트롤 추가**: `security_checker.py`의 `_load_controls()`에 추가
3. **새로운 AWS 서비스 지원**: `report_generator.py`의 쿼리 목록 확장
4. **성능 최적화**: 캐싱 로직 개선, 병렬 처리 최적화
5. **UI/보고서 개선**: `report_generator.py`의 HTML/CSS 템플릿 수정

### 모듈별 개발 포인트
- **설정 변경**: `src/config.py` 수정
- **Steampipe 연동 개선**: `src/steampipe_client.py`
- **보안 체크 추가**: `src/security_checker.py`
- **보고서 기능 확장**: `src/report_generator.py`
- **새 MCP 도구 추가**: `src/mcp_tools.py`

## 📄 라이선스

MIT License - 자유롭게 사용, 수정, 배포 가능

## 🔗 관련 링크

- [Steampipe](https://steampipe.io/)
- [AWS Foundational Security Best Practices](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp.html)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- [Amazon Q Developer](https://aws.amazon.com/q/developer/)

---

**⭐ 만약 이 프로젝트가 도움이 되었다면 Star를 눌러주세요!**