# Quick Start Guide

## 🚀 One-Command Startup

### Option 1: Using Startup Scripts (Recommended)

**Windows:**
```bash
# Just double-click or run:
start.bat
```

**Linux/Mac:**
```bash
# Make executable (first time only)
chmod +x start.sh

# Run
./start.sh
```

This will automatically start:
- ✅ Backend Server (Node.js) on `http://localhost:5000`
- ✅ Frontend (React) on `http://localhost:5173`
- ✅ Scanner Engine (Python) on `http://localhost:8000`

Press `Ctrl+C` (or any key on Windows) to stop all services.

---

### Option 2: Using NPM Scripts

```bash
# Install concurrently (first time only)
npm install

# Start all services
npm start
```

---

### Option 3: Manual (3 Terminals)

If you prefer manual control:

**Terminal 1 - Backend:**
```bash
cd backend
npm run dev
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

**Terminal 3 - Scanner:**
```bash
cd scanner-core
python api_bridge.py
```

---

## 📦 First-Time Setup

### 1. Install Dependencies

**All at once:**
```bash
npm run install:all
```

**Or manually:**
```bash
# Backend
cd backend
npm install

# Frontend
cd frontend
npm install

# Scanner
cd scanner-core
pip install -r requirements.txt
```

### 2. Environment Configuration

Create `.env` files if needed:

**backend/.env:**
```env
PORT=5000
DATABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_key
```

**scanner-core/.env:**
```env
SCANNER_PORT=8000
LOG_LEVEL=INFO
```

### 3. Start the Application

```bash
# Windows
start.bat

# Linux/Mac
./start.sh

# Or using npm
npm start
```

### 4. Access the Application

Open your browser and navigate to:
```
http://localhost:5173
```

---

## 🛠️ Development Workflow

### Running Individual Services

**Backend only:**
```bash
npm run start:backend
```

**Frontend only:**
```bash
npm run start:frontend
```

**Scanner only:**
```bash
npm run start:scanner
```

### Building for Production

```bash
npm run build
```

This creates optimized production builds in `frontend/dist`.

---

## 🔧 Troubleshooting

### Port Already in Use

If you get "port already in use" errors:

**Windows:**
```bash
# Find process using port 5000
netstat -ano | findstr :5000

# Kill process (replace PID)
taskkill /PID <PID> /F
```

**Linux/Mac:**
```bash
# Find and kill process
lsof -ti:5000 | xargs kill -9
```

### Python Module Not Found

```bash
cd scanner-core
pip install -r requirements.txt
```

### Node Modules Missing

```bash
# In backend or frontend directory
npm install
```

---

## 📊 Service Status

Check if all services are running:

| Service | URL | Status Check |
|---------|-----|--------------|
| **Frontend** | http://localhost:5173 | Should show UI |
| **Backend** | http://localhost:5000/health | Should return `{"status":"ok"}` |
| **Scanner** | http://localhost:8000/health | Should return `{"status":"healthy"}` |

---

## 🎯 Next Steps

1. **Configure AI Assistant** (Optional)
   - Go to Settings → AI Assistant
   - Choose provider (OpenAI, Anthropic, Google, or Ollama)
   - Enter API key
   - Test connection

2. **Run Your First Scan**
   - Click "New Scan"
   - Enter target URL
   - Select scan type
   - Start scanning!

3. **View Project Capabilities**
   - Read [CAPABILITIES.md](file:///g:/project%20ii/vulnerability-scanner/CAPABILITIES.md) for a full feature list.

---

## 💡 Tips

- **Use `start.bat`/`start.sh`** for easiest startup
- **Keep terminals open** to see logs
- **Check browser console** for frontend errors
- **Monitor scanner logs** for detection details
- **Use AI Assistant** for vulnerability explanations

---

## 🆘 Need Help?

- Check `TROUBLESHOOTING.md` for common issues
- Review `AI_INTEGRATION.md` for AI setup
- See `VULNERABILITY_MODULES.md` for module details
- Open an issue on GitHub

---

**Happy Scanning! 🔒**
