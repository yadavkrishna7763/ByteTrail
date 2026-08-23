# ByteTrail

ByteTrail is a lightweight full-stack application designed with modular architecture for web interfaces, API services, database management, and automated report generation.

## Project Structure

```
ByteTrail/
├── backend/          # Python & FastAPI backend
│   ├── venv/         # Virtual environment
│   ├── main.py       # FastAPI application entry point
│   └── requirements.txt
├── database/         # Database schemas and migration scripts
│   └── schema.sql
├── frontend/         # Frontend user interface (HTML, CSS, JavaScript)
│   ├── app.js
│   ├── index.html
│   └── styles.css
├── reports/          # Directory for generated PDF output
├── .gitignore        # Git ignore rules for Python, Node, and artifacts
└── README.md         # Project documentation
```

## Prerequisites

- **Python**: 3.9+ installed
- **Git**

## Setup & Running the Backend

1. **Navigate to the `backend/` directory:**
   ```bash
   cd backend
   ```

2. **Create and activate a virtual environment:**
   - On macOS/Linux:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   - On Windows:
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Start the FastAPI development server:**
   ```bash
   uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```

5. **Verify the API:**
   Open [http://127.0.0.1:8000/ping](http://127.0.0.1:8000/ping) in your browser or run:
   ```bash
   curl http://127.0.0.1:8000/ping
   ```
   Expected response:
   ```json
   {"status": "ok"}
   ```

Interactive API documentation is available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).
