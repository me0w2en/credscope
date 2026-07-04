# credscope

Windows EVTX Security 로그에서 로그온 기록을 분석해, 침해 시점에 비밀번호가 노출되었을 수 있는 계정을 자동으로 식별하는 도구.

## 설치

```bash
pip install -e .
```

## 사용법

```bash
credscope <Security.evtx 경로>
```

## 개발 환경

```bash
pip install -e ".[dev]"
pytest
```
