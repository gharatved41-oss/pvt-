# VulnTwin AI (pvt-)

> **Detect • Validate • Remediate • Secure**  
> Enterprise-Grade Autonomous Cyber Digital Twin & Continuous Threat Exposure Management (CTEM) Platform.

---

## Architecture Overview

- **Digital Twin Engine**: Graph-based topology simulation modeling cloud networks, assets, and attack paths.
- **AEV Attack Simulation**: Path traversal, lateral movement validation, and deterministic exploit probability scoring.
- **AI Remediation Engine**: Automated contextual patch generation and closed-loop re-testing verification.
- **Threat Intelligence**: Real-time integration with AbuseIPDB, VirusTotal, and deterministic reputation heuristics.
- **Frontend**: High-density enterprise dashboard built with React, Vite, Next.js, Tailwind CSS, and Lucide Icons.
- **Backend**: FastAPI REST service with SQLite relational persistence and Google Gemini SDK integration.

---

## Modules

- `frontend/`: Full-featured React + Vite application (11 operational consoles).
- `web/`: Next.js modular dashboard with client-side RBAC and simulation state.
- `backend/`: FastAPI application providing graph engine, simulation, threat intel, and remediation APIs.
- `functions/`: Cloud functions and serverless background tasks.

---

## Quickstart

### Backend
```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8001 --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Web
```bash
cd web
npm install
npm run dev
```
