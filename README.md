# Btc-hackathon
# 🧠 Bittasker: Blockchain-Backed Productivity App with AI Coaching

**Bittasker** is a Flask-based productivity and task management platform that leverages:
- ✅ **Bitcoin timestamping** (via [OpenTimestamps](https://opentimestamps.org/))
- ⚡ **Lightning Network** for reward payouts
- 🤖 **Google Gemini AI (1.5 Pro)** for productivity coaching
- 👥 **Team collaboration**, tagging, and scheduling support

---

## 🚀 Features

- 🔐 User authentication (registration, login, logout)
- 📋 Task creation with priorities, deadlines, tags, and rewards (in sats)
- ✅ Task completion with verifiable timestamps stored on the Bitcoin blockchain
- ⚡ Automated Lightning reward payout for completed tasks
- 📊 AI-powered insights from Gemini 1.5 (task patterns, habits, time blocks)
- 👨‍👩‍👧‍👦 Team formation, task visibility across team, and role-based access
- 🔍 Chat history tracking and API health checks
- 🖼️ Placeholder image generator API
- 🌐 RESTful API design

---

## 🧪 Stack

- **Backend**: Flask, Flask-Login, SQLAlchemy, Flask-CORS
- **Database**: SQLite (default), easily extendable to PostgreSQL
- **Bitcoin Integration**: BlockCypher API, OpenTimestamps
- **Lightning**: LND REST API support
- **AI**: Google Generative AI (Gemini 1.5 Pro)
- **Authentication**: Session-based via Flask-Login
- **Deployment**: Works locally and with Docker or cloud setups

---

## ⚙️ Environment Variables

You must define the following in a `.env` file or your environment:

```bash
SECRET_KEY=your_secret_key_here
DATABASE_URI=sqlite:///bittasker.db
BITCOIN_TESTNET=True
BLOCKCHAIN_API_KEY=your_blockcypher_api_key
LIGHTNING_NODE_URL=https://your-lnd-node.com
LIGHTNING_API_KEY=your_lightning_api_key
LIGHTNING_MACAROON=hex_macaroon_here
GEMINI_API_KEY=your_google_gemini_key

# 1. Clone the repository
git clone https://github.com/yourusername/bittasker.git
cd bittasker

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python btc_app.py
